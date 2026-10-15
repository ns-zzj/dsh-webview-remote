// ============================================================
// dsh-remote-gateway / lib/gateway.js
//
// 纯 Node 反向代理内核 —— 不 import 任何 DSH 包。
// 这一点是刻意的：它因此可以脱离 DSH 单独起、单独实测（对着正在运行的
// 127.0.0.1:19387 打），不需要重启 DSH 宿主。
//
// ── 它解决什么 ────────────────────────────────────────────────
// DSH 的 Web 服务只绑 127.0.0.1，且 /api 有一道 Host/Origin 围栏，
// 非 loopback 客户端（手机）默认进不来。本模块在别处另开一个监听口，
// 先做自己的密码鉴权，然后把请求转发给 127.0.0.1:<targetPort>。
//
// ── 关于上游的三个事实 ────────────────────────────────────────
// 【已实测】围栏不过 → 403；过围栏但没认证 → 401。
//          （本机实测：/api/ 带 Host: evil.example → 403；
//            正常 Host 无 cookie → 401）
// 【已读码】围栏规则：/api 的 Host 必须是 loopback 或 trustedHosts 命中；
//          请求带 Origin 时，Origin 的 host:port 必须等于 Host；
//          带 sec-fetch-site: cross-site 直接拒。
// 【已读码】DSH 会话 = 进程启动 token → 签名 cookie。token 只在「根路径交换」
//          那一步被接受（查询参数名就是 token），每次进程重新随机；
//          cookie 把 hostname+port 写进 cookie 名和签名载荷。
//
// ── 于是本模块的两个核心策略 ──────────────────────────────────
// 1) 对上游【一律】改写 Host 为 127.0.0.1:<targetPort>，同时把 Origin /
//    referer 归一到同一个 authority。绝不能有时原样转发 —— 否则 DSH 每次
//    算出的 authority 不同、cookie 名对不上，会在 401 之间来回跳。
// 2) 在根请求上替客户端注入当前进程的启动 token（由调用方通过 resolveToken
//    提供）。这样手机端永远不需要看见 token，也不需要「reopen the URL
//    printed by dsh web」。
//
// ── 安全边界（必须写清楚，这是策略 1 的代价）──────────────────
// 策略 1 等于把 DSH 那道 Origin 围栏，对「已通过本模块鉴权的流量」主动失效。
// 所以安全边界完全落在本模块的密码上 —— 密码泄露 = 对方能在本机执行任意命令。
// 这就是为什么 createGateway() 拒绝空密码：失败关闭，而不是开一个没锁的门。
// ============================================================

import http from 'node:http'
import { createHash, createHmac, scryptSync, timingSafeEqual } from 'node:crypto'

const LOOPBACK = '127.0.0.1'
const PREFIX = '/__gateway'
const DAY_MS = 86400000
const SCRYPT_SALT = 'dsh-remote-gateway/v1'

/** 本网关自己的会话 cookie 名（与 DSH 的 dsh-auth-* 区分开）。 */
export const GATEWAY_COOKIE = 'dsh-gw'

/** DSH 会话 cookie 的前缀（完整名字里还带 authority 的哈希）。 */
const DSH_COOKIE_PREFIX = 'dsh-auth-'

/**
 * 从客户端带来的 DSH 会话 cookie 里读出 `expiresAt` —— **只看不验签名**。
 *
 * 为什么不需要密钥：cookie 值是 `v1.<base64url(JSON)>.<hmac>`，第二段解出来就是
 * `{ version, authority, issuedAt, expiresAt }`。我们只用它判断"这张 cookie 是不是
 * 已经过期"，**不验证真伪** —— 真伪由 DSH 自己验。我们判断错了最多多一次重定向，
 * 没有安全问题（authority 由网关改写后固定，攻击者也无法借此换到别的 authority）。
 *
 * @returns 过期时刻（毫秒）；解不出来返回 undefined。
 */
function dshSessionExpiresAt(cookieHeader) {
  if (typeof cookieHeader !== 'string') return undefined
  for (const part of cookieHeader.split(';')) {
    const at = part.indexOf('=')
    if (at === -1) continue
    if (!part.slice(0, at).trim().startsWith(DSH_COOKIE_PREFIX)) continue
    const segments = part.slice(at + 1).trim().split('.')
    if (segments.length !== 3 || segments[0] !== 'v1') continue
    try {
      const body = segments[1].replaceAll('-', '+').replaceAll('_', '/')
      const padding = '='.repeat((4 - (body.length % 4)) % 4)
      const payload = JSON.parse(Buffer.from(body + padding, 'base64').toString('utf8'))
      if (Number.isFinite(payload?.expiresAt)) return payload.expiresAt
    } catch {
      /* 解不出来 → 当作"没有可用 cookie" */
    }
  }
  return undefined
}

/** 客户端是否持有一张**看起来还没过期**的 DSH 会话 cookie。 */
function hasLiveDshSession(cookieHeader) {
  const expiresAt = dshSessionExpiresAt(cookieHeader)
  return expiresAt !== undefined && expiresAt > Date.now()
}

/** hop-by-hop 头：转发时必须丢掉，否则 Node 的成帧会被搞坏。 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

const sha256 = (value) => createHash('sha256').update(String(value), 'utf8').digest()

const base64url = (buf) =>
  buf.toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '')

/**
 * 定长时间比较两个秘密。
 * 先各自 sha256 再比，这样两个输入长度不同也不会让 timingSafeEqual 抛错，
 * 同时比较耗时与输入长度无关。
 */
function sameSecret(a, b) {
  return timingSafeEqual(sha256(a), sha256(b))
}

/** 解析 Cookie 头成普通对象。重复名取后者（与实际浏览器行为一致）。 */
function parseCookies(header) {
  const out = {}
  if (typeof header !== 'string') return out
  for (const part of header.split(';')) {
    const at = part.indexOf('=')
    if (at === -1) continue
    const name = part.slice(0, at).trim()
    if (name !== '') out[name] = part.slice(at + 1).trim()
  }
  return out
}

/**
 * 会话 cookie 的签发/校验器。
 * 无状态：cookie 值就是 `<过期毫秒>.<HMAC>`，密钥由密码派生。
 * 好处是改密码即等于吊销所有设备，不需要任何存储。
 */
function makeSigner(password, sessionDays) {
  const key = scryptSync(password, SCRYPT_SALT, 32)
  const mac = (payload) => base64url(createHmac('sha256', key).update(payload).digest())
  return {
    issue() {
      const payload = String(Date.now() + sessionDays * DAY_MS)
      return `${payload}.${mac(payload)}`
    },
    verify(value) {
      if (typeof value !== 'string') return false
      const at = value.indexOf('.')
      if (at === -1) return false
      const payload = value.slice(0, at)
      const got = Buffer.from(value.slice(at + 1), 'utf8')
      const want = Buffer.from(mac(payload), 'utf8')
      if (got.length !== want.length || !timingSafeEqual(got, want)) return false
      const expiresAt = Number(payload)
      return Number.isSafeInteger(expiresAt) && expiresAt > Date.now()
    },
  }
}

// 【用户要求】这里**没有网页登录页**。
//
// 这个端口只负责 App（机器对机器）通信，**不负责给浏览器显示任何东西** ——
// 无凭据的直接 GET 就是"没有东西"：最小的 401，正文不携带页面。
// 登录界面只存在于客户端 App 里（原生 Flutter 表单）。
//
// 为什么这么做：
//   1) 登录页要是也成了网页，那用 App 就没意义了 —— 还不如直接用浏览器；
//   2) 网页登录页会白送一串麻烦：开放重定向、表单 CSRF、密码走 body、
//      还要维护一套只在浏览器里才走得到的 HTML 和样式。
//
// 于是原先的 loginPage / safeNext / readBody 三个辅助函数**一并删除** ——
// 它们只服务于那个已经不存在的东西。

/** 构造转发给上游的请求头：改写 authority、丢掉 hop-by-hop、摘掉我们自己的 cookie。 */
function upstreamHeaders(incoming, targetPort) {
  const headers = {}
  for (const [name, value] of Object.entries(incoming)) {
    if (value === undefined) continue
    const lower = name.toLowerCase()
    if (HOP_BY_HOP.has(lower)) continue
    headers[lower] = value
  }

  // ── 第 1 步：authority 归一。这是策略 1 的核心，不能省。
  const authority = `${LOOPBACK}:${targetPort}`
  const origin = `http://${authority}`
  headers.host = authority
  // DSH 的围栏要求 Origin 的 host:port 等于 Host。浏览器发来的 Origin 是
  // 网关自己的地址（如 http://192.168.1.110:8080），不改就会 403。
  if (headers.origin !== undefined) headers.origin = origin
  if (headers.referer !== undefined) {
    try {
      const ref = new URL(String(headers.referer))
      headers.referer = origin + ref.pathname + ref.search
    } catch {
      delete headers.referer
    }
  }

  // ── 第 2 步：摘掉网关自己的 cookie。上游不认识它，没必要让它看见。
  if (headers.cookie !== undefined) {
    const kept = String(headers.cookie)
      .split(';')
      .map((part) => part.trim())
      .filter((part) => part !== '' && !part.startsWith(`${GATEWAY_COOKIE}=`))
    if (kept.length === 0) delete headers.cookie
    else headers.cookie = kept.join('; ')
  }

  return headers
}

/** 上游响应头：同样丢掉 hop-by-hop，并把指向 loopback 的绝对 Location 改回相对。 */
function downstreamHeaders(upstream, targetPort) {
  const headers = {}
  for (const [name, value] of Object.entries(upstream)) {
    if (value === undefined) continue
    if (HOP_BY_HOP.has(name.toLowerCase())) continue
    headers[name] = value
  }
  const location = headers.location
  if (typeof location === 'string') {
    for (const base of [`http://${LOOPBACK}:${targetPort}`, `https://${LOOPBACK}:${targetPort}`]) {
      if (location.startsWith(base)) {
        const rest = location.slice(base.length)
        headers.location = rest === '' ? '/' : rest
        break
      }
    }
  }
  return headers
}

/**
 * 注入到 index.html 里的兼容垫片。
 *
 * ── 为什么需要 ────────────────────────────────────────────────
 * Android 的 **WebView 是一个可独立更新的系统组件**，和同一台机器上的 Chrome
 * 是两码事，版本可以差很远。实测在一台 Android 12 平板上遇到：
 *
 *     Promise.withResolvers  → undefined   （Chrome 119+ 才有）
 *     AbortSignal.any        → undefined   （Chrome 116+ 才有）
 *
 * 于是 DSH 的实时通道一建立就抛异常 → 客户端无限重连（console 里刷
 * `[connection] connection lost, retry #N`），而静态 HTML/CSS 照常渲染 ——
 * 因为那些不碰这两个 API。**同样的 origin 在手机 Chrome 里却完全正常。**
 *
 * ── 为什么注入在这里能生效 ────────────────────────────────────
 * 插在 `<head>` 之后的第一件事。它是**经典脚本**，解析到就立即执行；而页面自己
 * 那些 `<script type="module">` 默认是 defer 的，必然排在它后面。所以垫片一定先跑。
 *
 * 只补**确实缺失**的，并把补了哪些打到 console —— 这样下次一眼就能看出某台设备
 * 还缺什么，不用一个个猜。
 */
const CLIENT_SHIM = `<script>
// ── 这个垫片的自我诊断原则 ────────────────────────────────────────
// 它跑在设备上的 WebView 里，出错时外面完全看不见（没连 DevTools 就是黑箱）。
// 所以：
//   1) 先把状态对象挂到 globalThis 上，再干别的 —— 这样即使中间抛异常，
//      宿主 App 的调试面板里也能看到 installed 和 error 两个字段。
//   2) 整段包在 try/catch 里，异常写进 report.error，而不是无声消失。
//   3) 里面不许出现反斜杠转义，也不许出现反引号 —— 这段代码写在 gateway.js
//      的模板字符串里：反斜杠会被吃掉（曾使整段脚本语法错误、垫片全失效），
//      反引号会直接把模板字符串提前结束（曾使 gateway.js 自己都加载不了）。
//      这两个坑都踩过，见 tools/shim-check.mjs。
(function () {
  var report = globalThis.__DSH_GATEWAY_SHIM__ = {
    ua: navigator.userAgent,
    kernel: null,
    minKernel: 114,
    installed: [],
    error: null,
    enterShim: false,
    keyboardShim: false
  };
  var installed = report.installed;

  try {

  // Promise.withResolvers —— ES2024，Chrome 119+
  if (typeof Promise.withResolvers !== 'function') {
    Promise.withResolvers = function () {
      var resolve, reject;
      var promise = new Promise(function (res, rej) { resolve = res; reject = rej; });
      return { promise: promise, resolve: resolve, reject: reject };
    };
    installed.push('Promise.withResolvers');
  }

  // AbortSignal.any —— Chrome 116+
  if (typeof AbortSignal.any !== 'function') {
    AbortSignal.any = function (signals) {
      var controller = new AbortController();
      function onAbort(event) {
        for (var i = 0; i < signals.length; i++) {
          signals[i].removeEventListener('abort', onAbort);
        }
        controller.abort(event.target.reason);
      }
      for (var i = 0; i < signals.length; i++) {
        var signal = signals[i];
        if (signal.aborted) { controller.abort(signal.reason); return controller.signal; }
        signal.addEventListener('abort', onAbort);
      }
      return controller.signal;
    };
    installed.push('AbortSignal.any');
  }

  // AbortSignal.timeout —— Chrome 103+
  if (typeof AbortSignal.timeout !== 'function') {
    AbortSignal.timeout = function (ms) {
      var controller = new AbortController();
      setTimeout(function () {
        controller.abort(new DOMException('The operation timed out.', 'TimeoutError'));
      }, ms);
      return controller.signal;
    };
    installed.push('AbortSignal.timeout');
  }

  // Object.hasOwn —— Chrome 93+
  if (typeof Object.hasOwn !== 'function') {
    Object.hasOwn = function (object, key) {
      return Object.prototype.hasOwnProperty.call(object, key);
    };
    installed.push('Object.hasOwn');
  }

  // URL.canParse —— Chrome 120+
  if (typeof URL.canParse !== 'function') {
    URL.canParse = function (input, base) {
      try { new URL(input, base); return true; } catch (e) { return false; }
    };
    installed.push('URL.canParse');
  }

  // structuredClone —— Chrome 98+
  if (typeof structuredClone !== 'function') {
    globalThis.structuredClone = function (value) { return JSON.parse(JSON.stringify(value)); };
    installed.push('structuredClone(JSON 近似实现)');
  }

  function defineArrayMethod(name, fn) {
    if (typeof Array.prototype[name] === 'function') return;
    Object.defineProperty(Array.prototype, name, { value: fn, writable: true, configurable: true });
    installed.push('Array.prototype.' + name);
  }

  // Array.prototype.at —— Chrome 92+
  defineArrayMethod('at', function (n) {
    n = Math.trunc(n) || 0;
    if (n < 0) n += this.length;
    return (n < 0 || n >= this.length) ? undefined : this[n];
  });
  // findLast / findLastIndex —— Chrome 97+
  defineArrayMethod('findLast', function (predicate, thisArg) {
    for (var i = this.length - 1; i >= 0; i--) {
      if (predicate.call(thisArg, this[i], i, this)) return this[i];
    }
    return undefined;
  });
  defineArrayMethod('findLastIndex', function (predicate, thisArg) {
    for (var i = this.length - 1; i >= 0; i--) {
      if (predicate.call(thisArg, this[i], i, this)) return i;
    }
    return -1;
  });
  // 非破坏性数组方法 —— Chrome 110+
  defineArrayMethod('toSorted', function (compare) {
    return Array.prototype.slice.call(this).sort(compare);
  });
  defineArrayMethod('toReversed', function () {
    return Array.prototype.slice.call(this).reverse();
  });
  defineArrayMethod('toSpliced', function (start, deleteCount) {
    var copy = Array.prototype.slice.call(this);
    var rest = Array.prototype.slice.call(arguments, 2);
    copy.splice.apply(copy, [start, deleteCount].concat(rest));
    return copy;
  });
  defineArrayMethod('with', function (index, value) {
    var copy = Array.prototype.slice.call(this);
    var i = index < 0 ? this.length + index : index;
    if (i < 0 || i >= copy.length) throw new RangeError('Invalid index');
    copy[i] = value;
    return copy;
  });

  // Object.groupBy / Map.groupBy —— Chrome 117+
  if (typeof Object.groupBy !== 'function') {
    Object.groupBy = function (items, keyFn) {
      var out = Object.create(null);
      var i = 0;
      for (var item of items) {
        var key = keyFn(item, i++);
        (out[key] || (out[key] = [])).push(item);
      }
      return out;
    };
    installed.push('Object.groupBy');
  }
  if (typeof Map.groupBy !== 'function') {
    Map.groupBy = function (items, keyFn) {
      var out = new Map();
      var i = 0;
      for (var item of items) {
        var key = keyFn(item, i++);
        var bucket = out.get(key);
        if (bucket === undefined) { bucket = []; out.set(key, bucket); }
        bucket.push(item);
      }
      return out;
    };
    installed.push('Map.groupBy');
  }

  // ── 曾经补过 crypto.randomUUID —— 已删除（2026-10-14）────────────
  //
  // 背景：我们的源是 http://<局域网IP>:<端口>，不是可信源 → isSecureContext=false
  // → crypto.randomUUID 这类 [SecureContext] 门控的 API 缺失。当初怀疑 DSH 客户端
  // 要用它生成 clientId、缺了就建不起 $events，于是补了一个等价实现。
  //
  // 后来查清了：**DSH 根本不用这个 API。**
  //   packages/util/crypto/src/index.ts 的 randomUUID() 是用
  //   crypto.getRandomValues 自己造的 —— 而 getRandomValues **不受**安全上下文限制。
  //   那个模块的注释还明确写着"这一份实现取代了各处调用者自己的补丁"，
  //   并有 lint 规则把调 crypto.randomUUID 的人指过去。
  // 实测也印证：两台设备上 crypto.getRandomValues 都在。
  //
  // 而且**真原因早就被证明不是它** —— 那次补上之后症状照旧（见 开发思路.md §17）。
  // 本次的真原因与安全上下文无关，见仓库根目录「鸿蒙ArkWeb-onLine错报-调查报告.md」。
  //
  // ⚠️ 上面那几段**版本补丁不要动**（Promise.withResolvers / AbortSignal.any /
  //    URL.canParse / Object.groupBy / Map.groupBy）—— 那是安卓 Chrome/114 缺的，
  //    删了安卓会立刻坏（开发思路.md §17 记的那个"一直重连中"就是它）。

  // ── 内核版本下限检查 ─────────────────────────────────────────
  // 本项目的支持下限：Chrome / WebView 【114】（见 开发思路.md §12）。
  // 低于它不保证可用 —— 但至少要说清楚，而不是让人对着空页面猜半天。
  //
  // 内核版本识别：故意不用正则。这段代码写在 gateway.js 的模板字符串里，
  // 而"反斜杠加字母"这种非法转义会被吃掉反斜杠，使正则变成语法错误 ——
  // 那会让整段 script 作废、垫片全部失效，而症状又和"内核太老"一模一样，
  // 极容易误判。纯字符串扫描没有这个风险。
  var MIN_KERNEL = report.minKernel;
  var ua = navigator.userAgent;
  var kernel = null;
  var marker = ua.indexOf('Chrome/');
  if (marker >= 0) {
    var digits = '';
    for (var index = marker + 7; index < ua.length; index++) {
      var ch = ua.charAt(index);
      if (ch < '0' || ch > '9') break;
      digits += ch;
    }
    if (digits !== '') kernel = parseInt(digits, 10);
  }
  report.kernel = kernel;

  console.log('[dsh-gateway-shim] UA: ' + navigator.userAgent);
  console.log('[dsh-gateway-shim] 本次补上的 API: ' + (installed.length > 0 ? installed.join(', ') : '(无)'));

  if (kernel === null) {
    console.warn('[dsh-gateway-shim] 认不出内核版本；本项目支持下限是 Chrome/' + MIN_KERNEL + '。');
  } else if (kernel < MIN_KERNEL) {
    console.warn(
      '[dsh-gateway-shim] 内核 Chrome/' + kernel + ' 低于支持下限 Chrome/' + MIN_KERNEL +
      '：缺失的 API 会尽量垫，但不保证实时通道可用。'
    );
  } else {
    console.log('[dsh-gateway-shim] 内核 Chrome/' + kernel + '，满足支持下限 Chrome/' + MIN_KERNEL + '。');
  }
  } catch (error) {
    // 任何一步失败都写进 report.error，宿主 App 的调试面板会显示出来。
    // 注意：这只兜得住运行时异常。如果整段是**语法错误**，块内代码一行都不会跑，
    // 那种情况只能靠外部的 parse 检查（tools/shim-check.mjs）。
    report.error = String((error && error.message) || error);
    console.error('[dsh-gateway-shim] 垫片执行失败：', error);
  }
})();
</script>`

/**
 * 移动端的「回车改成换行」注入。
 *
 * ── 背景 ──────────────────────────────────────────────────────
 * DSH 的桌面行为是「**回车发送**、Shift+回车换行」。而**手机 IME 没有 Shift**，
 * 于是手机上根本打不出换行 —— 一按回车就发出去。
 * （DSH 没有对应的配置项：已查过 ui-conversation / ui-chat 的实时 schema，
 *  能配的只有 busyEnter、transcriptView、performanceUsage、linkOpening。）
 *
 * ── 做法 ──────────────────────────────────────────────────────
 * 把「无修饰键的回车」改写成换行；发送交给界面上的发送按钮。
 *
 * 两个关键点：
 *   1) **捕获阶段** —— React 17+ 把事件监听挂在根容器上，捕获阶段先于它执行，
 *      这里的 stopPropagation 能让应用完全看不到这个回车。
 *   2) **必须用 execCommand** —— 它会把换行真正写进输入框并触发 input 事件，
 *      React 的受控组件才会读到新值。直接改 DOM 的 value 会被下一次 render 覆盖。
 *
 * 只在移动端启用（桌面保持"回车发送"原样），且只处理 textarea / contenteditable
 * —— 单行 input 里换行没意义，拦了只会把它弄坏。
 */
const MOBILE_ENTER_SHIM = `<script>
(function () {
  var TAG = '[dsh-gateway-shim:enter]';
  if (!/Android|iPhone|iPad|iPod|HarmonyOS|Mobile/i.test(navigator.userAgent)) return;

  function isMultilineEditable(el) {
    if (!el) return false;
    if (el.tagName === 'TEXTAREA') return true;
    return el.isContentEditable === true;
  }

  // 只用来判断"那一下到底有没有产生效果"，**不参与插入**。
  function snapshot(el) {
    if (!el) return '';
    return el.tagName === 'TEXTAREA' ? (el.value || '') : (el.textContent || '');
  }

  function insertNewline(el) {
    // 关键：**我们自己绝不改 DOM**。
    //
    // 早先的实现用 document.execCommand('insertLineBreak' / 'insertText') 直接改 DOM。
    // 这么做绕过了 DSH 自己的状态管理：它下一次重绘时按自己的状态把内容写回去，
    // 结果是**用户刚打的字整段消失**（手机上实测到的就是这个）。
    //
    // 现在改成：合成一个 shiftKey=true 的 Enter 交给页面，让 **DSH 自己的多行
    // 代码路径**去插入。它自己插的内容，它自己的状态自然是一致的。
    //
    // 失败模式也更安全：如果页面根本不看 keydown（或不用 Shift+Enter 表示换行），
    // 最坏结果只是"回车没反应"，**不会吃掉用户打的内容**。
    var before = snapshot(el);

    var fake = new KeyboardEvent('keydown', {
      key: 'Enter',
      code: 'Enter',
      shiftKey: true,
      bubbles: true,
      cancelable: true,
      composed: true
    });

    // KeyboardEvent 的构造器**不接受** keyCode / which（它们是遗留的只读属性，
    // 传进去会被忽略、读出来是 0）。有些老式处理器就认 keyCode，所以在实例上
    // 单独把它们定义出来 —— 定义失败也无所谓，event.key 已经是对的。
    try {
      Object.defineProperty(fake, 'keyCode', { get: function () { return 13; } });
      Object.defineProperty(fake, 'which', { get: function () { return 13; } });
    } catch (e) { /* 忽略 */ }

    el.dispatchEvent(fake);

    return snapshot(el) !== before;
  }

  var announced = false;

  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Enter') return;
    // 带修饰键的 Enter 一律放行（我们合成的那个事件也走这条，所以不会被自己拦第二次）
    if (event.shiftKey || event.ctrlKey || event.metaKey || event.altKey) return;
    if (!isMultilineEditable(event.target)) return;
    // 输入法组字中不拦：那一下回车是"确认候选词"
    if (event.isComposing || event.keyCode === 229) return;

    event.preventDefault();
    event.stopPropagation();

    var effective = false;
    try {
      effective = insertNewline(event.target);
    } catch (e) {
      effective = false;
    }

    if (!announced) {
      announced = true;
      console.log(
        TAG + ' 回车已改写为换行，发送请点发送按钮（本次' +
        (effective ? '生效' : '没生效 —— 页面可能不用 Shift+Enter 表示换行') + '）'
      );
    }
  }, true);

  globalThis.__DSH_GATEWAY_SHIM__ = Object.assign(globalThis.__DSH_GATEWAY_SHIM__ || {}, {
    enterShim: true
  });
})();
</script>`

/**
 * 键盘弹出时的「零重排」补丁。
 *
 * ── 问题 ──────────────────────────────────────────────────────
 * Android 11+ 的键盘弹出/收起是**动画**，窗口尺寸在约 250ms 内连续变化。
 * 配上 `adjustResize`，WebView 会被连续缩放 → 页面连续重排几十次 → 明显卡顿。
 * （这是移动网页里很典型的一类卡顿。）
 *
 * ── 做法 ──────────────────────────────────────────────────────
 * 1) manifest 里把 `windowSoftInputMode` 改成 **`adjustNothing`**
 *    —— 窗口**不再改尺寸**，于是零重排。
 * 2) 这里用 `visualViewport` 量出被键盘遮住的高度，把 `body` 整体**位移**上去。
 *    `transform` 只走合成器、**不触发布局**，所以同样不产生重排。
 *
 * DSH 的输入框在底部，整体上移后正好落在键盘上方可见。
 *
 * ⚠️ 副作用：`body` 一旦被 transform，其内部的 `position: fixed` 元素会改为
 * 相对 body 定位。若发现某些面板错位，就把这里改成"只位移输入框的容器"。
 */
// ⚠️ 【已停用，2026-10-01】不再注入。代码留着只为对照，别加回 injection。
//
// 为什么停用：它靠 transform 把内容顶上去"模拟"窗口缩小，但
//   · 直接 transform body → 实测在鸿蒙上**整页被顶上去**，顶部栏推出屏幕；
//   · 改成只抬输入框那一条 → 底部消息仍被键盘挡住、滚不到，
//     因为它根本没改变可用的布局高度。
// 正解是**让窗口照常缩小**（Android 的 adjustResize / Flutter 的 viewInsets），
// 再用 Dart 侧的 _DebouncedSize 把平台视图的 resize 合并成一次 ——
// 布局正确 + 只重排一次。这个补丁是绕路。
const KEYBOARD_INSET_SHIM = `<script>
(function () {
  if (!/Android|iPhone|iPad|iPod|HarmonyOS|Mobile/i.test(navigator.userAgent)) return;
  var vv = window.visualViewport;
  if (!vv) return;

  var applied = -1;
  var moved = null;

  // 抬谁？—— 只抬输入框那一条，不要抬整个页面。
  //
  // 实测教训（鸿蒙，2026-10-01）：直接 transform body 会把整页顶上去，
  // 顶部栏被推出屏幕，体验很怪。
  // 现在从焦点元素往上找"底部那一条"：
  //   横向够宽（≥70% 视口）× 不太高（≤60% 视口高）× 贴着底部（或 fixed/sticky）
  // 取【最外层】满足条件的那个 —— 再往上一级就是整页容器，会被"不太高"排除。
  // 找不到就退回 body（与旧行为一致，不会更糟）。
  // 无论平移谁，transform 都只走合成器、不触发布局 —— 零重排的性质不变。
  function pickTarget() {
    var node = document.activeElement;
    if (!node || typeof node.getBoundingClientRect !== 'function') return document.body;

    var viewportHeight = window.innerHeight;
    var viewportWidth = window.innerWidth;
    var best = null;
    var current = node;

    while (current && current !== document.documentElement) {
      var rect = current.getBoundingClientRect();
      var position = window.getComputedStyle(current).position;
      var spansWidth = rect.width >= viewportWidth * 0.7;
      var shortEnough = rect.height > 0 && rect.height <= viewportHeight * 0.6;
      var anchoredBottom = rect.bottom >= viewportHeight * 0.85;
      var positioned = position === 'fixed' || position === 'sticky';
      if (spansWidth && shortEnough && (anchoredBottom || positioned)) best = current;
      current = current.parentElement;
    }
    return best || document.body;
  }

  function apply() {
    // 这个垫片注入在 <head> 里，**那一刻还没有 document.body**。
    // 直接取 body.style 会抛 TypeError，而抛出点在这段脚本的中间 ——
    // 后面的 keyboardShim 标记也一并写不上（实测症状：调试面板里看不到
    // keyboardShim）。所以先判空，再把 apply 挂到 DOMContentLoaded 上补一次。
    if (!document.body) return;

    // 键盘高度 ≈ 布局视口高 - 视觉视口高
    var inset = Math.max(0, Math.round(window.innerHeight - vv.height));
    if (inset === applied) return;
    applied = inset;

    var target = inset > 0 ? pickTarget() : (moved || document.body);
    if (target !== moved) {
      if (moved) moved.style.transform = '';
      moved = target;
    }
    target.style.transformOrigin = 'top left';
    target.style.transform = inset > 0 ? 'translateY(-' + inset + 'px)' : '';
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', apply);
  }

  vv.addEventListener('resize', apply);
  vv.addEventListener('scroll', apply);
  window.addEventListener('orientationchange', apply);
  // 焦点换到别的容器（比如切另一个输入框）时，重新挑一次平移目标
  document.addEventListener('focusin', function () { applied = -1; apply(); }, true);
  apply();

  globalThis.__DSH_GATEWAY_SHIM__ = Object.assign(globalThis.__DSH_GATEWAY_SHIM__ || {}, {
    keyboardShim: true
  });
  console.log('[dsh-gateway-shim:keyboard] 键盘零重排补丁已装');
})();
</script>`

/**
 * 把页面里的错误/告警**回传**到网关。
 *
 * 为什么需要（2026-10-05）：鸿蒙上完全看不到 WebView 内部的报错 ——
 *   · Dart 的 debugPrint 进不了 hilog（实测）
 *   · ArkWeb 自己的 console 也不出现在 hilog 里（实测）
 *   · 手机上没有 DevTools
 * 而"页面加载正常、UI 却报连接异常"这类问题，答案一定在页面的 JS 报错里。
 * 所以让页面主动把错误发给网关，由网关写进日志。
 *
 * 只回传 error / unhandledrejection / console.error / console.warn，
 * 且每个页面最多 300 条。原来是 40 —— 实测太低：一个过宽的探针就能吃掉 24 条，
 * 结果真正关键的那几行（比如 open 触发时的 readyState）反而被挤掉了。
 */
const PAGE_LOG_SHIM = `<script>
(function () {
  var ENDPOINT = '/__gateway/log';
  var sent = 0;
  function send(kind, text) {
    if (sent > 300) return;
    sent++;
    // 带上**页面自己的时钟**（相对页面开始的毫秒数）。
    // 为什么：这些回传是异步的，到达网关的先后可能和页面里真实发生的先后不一致。
    // 有了页面时钟，即使乱序到达也能重新排回去 —— 这是排查 ArkWeb 时序问题的前提。
    var pageMs = -1;
    try {
      if (typeof performance !== 'undefined' && performance.now) pageMs = Math.round(performance.now());
    } catch (e) { /* 取不到就留 -1 */ }
    var tag = pageMs >= 0 ? '(+' + pageMs + 'ms) ' : '';
    var body = kind + ': ' + tag + String(text).slice(0, 2000);
    try {
      if (navigator.sendBeacon) navigator.sendBeacon(ENDPOINT, body);
      else fetch(ENDPOINT, { method: 'POST', body: body, keepalive: true });
    } catch (e) { /* 回传失败绝不能影响页面 */ }

    // ── 兜底通道：把内容塞进一个普通 GET 的路径里（2026-10-05 加）──────
    // 为什么必须要有：实测在这台设备上 sendBeacon 完全不出现于网关日志
    //（垫片确实注入了、语法也 OK、gateway 侧的 [ws] 日志照常）——
    // 也就是"诊断通道本身坏了"，而它坏掉的样子恰好伪装成"页面很安静"，
    // 让排查彻底瞎掉。普通 GET 是最难失败的一条路：网关的 [req] 日志必然会记下它。
    try {
      var short = kind + ': ' + tag + String(text).slice(0, 600);
      fetch('/__shimlog/' + encodeURIComponent(short), { keepalive: true }).catch(function () {});
    } catch (e) { /* 同上 */ }
  }
  window.addEventListener('error', function (event) {
    send('error',
      (event.message || '') + ' @ ' + (event.filename || '?') +
      ':' + (event.lineno || 0) + ':' + (event.colno || 0));
  }, true);
  window.addEventListener('unhandledrejection', function (event) {
    var reason = event.reason;
    send('unhandledrejection',
      (reason && reason.message) ? reason.message : String(reason));
  }, true);
  var originalError = console.error;
  console.error = function () {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) {
      var item = arguments[i];
      parts.push(item instanceof Error ? (item.message + ' | ' + item.stack) : String(item));
    }
    send('console.error', parts.join(' '));
    return originalError.apply(console, arguments);
  };
  var originalWarn = console.warn;
  console.warn = function () {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]));
    send('console.warn', parts.join(' '));
    return originalWarn.apply(console, arguments);
  };

  // console.log / info 也拦 —— 为什么（2026-10-05）：
  // 之前只拦 error/warn，结果一条都没收到，说明失败是被静默吞掉的。
  // 但**连接状态**这类诊断信息通常走的是普通 log。所以把 log 也接上，
  // 每条截断到 300 字符、总量仍受 send() 的 40 条上限约束。
  var originalLog = console.log;
  console.log = function () {
    try {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]).slice(0, 300));
      send('console.log', parts.join(' '));
    } catch (e) { /* 忽略 */ }
    return originalLog.apply(console, arguments);
  };
  var originalInfo = console.info;
  console.info = function () {
    try {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]).slice(0, 300));
      send('console.info', parts.join(' '));
    } catch (e) { /* 忽略 */ }
    return originalInfo.apply(console, arguments);
  };

  // console.debug 也要拦（2026-10-05 加）。
  // 为什么：之前只拦 log/info/warn/error，页面显得"完全沉默"，一条插件相关的
  // 日志都没有 —— 而这类运行时（Cordis 插件系统）通常把激活/连接过程打在
  // debug 级别上。不拦它，就等于把最可能说话的那条路堵住了。
  var originalDebug = console.debug;
  console.debug = function () {
    try {
      var parts = [];
      for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]).slice(0, 300));
      send('console.debug', parts.join(' '));
    } catch (e) { /* 忽略 */ }
    return originalDebug.apply(console, arguments);
  };

  // ── 已删除的两个探针（2026-10-05 收尾）────────────────────────────
  //
  // 这里原来有两个用调用栈包名做判断的探针：包 AbortController（看连接循环有没有跑）
  // 和包 AbortSignal.any（看有没有执行到 pumpEvents）；另外还包了
  // crypto.getRandomValues 来数"疑似第几次流 open"。
  //
  // 删掉的原因：
  //   1) 结论已经拿到了 —— 连接循环确实在跑（日志里出现过"连接层创建了 AbortController"），
  //      而 $events 依旧没发出去，所以目标转移到"发帧之前卡在哪"，不在这两个 API 上。
  //   2) 它们都挂在热路径上：每个 AbortController 都要取一次调用栈再搜字符串，开销实打实。
  //   3) crypto.getRandomValues 那个钩子太宽 —— 每条一元 RPC 都会触发（RpcId 也用随机数），
  //      实测一个页面刷出 24 条噪音，把 send 的条数预算吃光，反而把关键日志挤没了。
  //
  // 现在保留的是真正有用的那几类：WebSocket 生命周期与收发帧、AbortController.abort
  // 的吞错捕获、console 钩子、窗口错误钩子、以及一次性的能力探测。

  // ── 抓"被吞掉的错误"：钩 AbortController.abort（2026-10-05 加）────
  //
  // 为什么必须这么做：DSH 客户端的 ConnectionController 在生成源失败时，
  // 唯一的动作是调用 AbortController 的 abort(error) —— **不打印任何东西**
  //（见 packages/client/connection/src/client/connection.ts 的 catch 分支）。
  // 所以页面上完全看不到报错，我们一直只能看到"$events 没发出去"这个结果，
  // 看不到原因。
  //
  // 而那个 error 对象**唯一的去处就是 abort(reason)**，
  // 所以钩住它就能把消息和堆栈打出来 —— 堆栈会直接指到出错的那一行。
  //
  // ⚠️ 注意：这个文件里整段垫片是模板字符串，**注释里绝不能出现反引号**
  //（写这一版时就因为一句带反引号的说明把字符串截断、导致语法错误，
  // 见开发思路.md 第 13 节记的那个坑）。
  // 注意：这一段必须整体包在 try/catch 里。
  // 加它的时候我没包，结果整个 PAGE_LOG_SHIM 在运行期抛错 ——
  // 症状是日志里**连 UA / probe 那些行都消失了**（因为 send 也是这段里定义的），
  // 而网关侧的 [ws] 日志照常，非常容易被误读成"垫片没被注入"。
  // 教训：诊断代码永远不能有能力弄死被诊断的东西。
  var NativeAbortController = window.AbortController;
  if (typeof NativeAbortController === 'function' && NativeAbortController.prototype) {
    try {
      var nativeAbort = NativeAbortController.prototype.abort;
      NativeAbortController.prototype.abort = function (reason) {
        try {
          if (arguments.length > 0 && reason instanceof Error) {
            // ⚠️ 这段里一个反斜杠都不能出现：整段垫片是模板字符串，
            // 反斜杠会被它先吃掉。加这一段时连着栽了两次 ——
            // 先是写了"换行"的转义写法，接着在"提醒别写转义"的注释里
            // 举例写了"正则空白"的转义写法（连注释里的例子本身都被吃掉），
            // 两次都把整段脚本弄成语法错误；而症状是"页面一条日志都没有"，
            // 看起来像 sendBeacon 坏了，白查了两轮。
            // 所以：换行一律用 String.fromCharCode(10) 表达。
            var newline = String.fromCharCode(10);
            var stack = String(reason.stack || '').split(newline).slice(0, 6).join(' || ');
            send('abort', reason.message + ' 堆栈: ' + stack.slice(0, 900));
          }
        } catch (e) { /* 记录失败不影响原行为 */ }
        return nativeAbort.apply(this, arguments);
      };
    } catch (e) { /* 钩不上就算了；绝不能因此让整段诊断脚本失效 */ }
  }


  // 为什么：网关侧已经证明通道健康、基线数据也到了客户端；但 UI 仍报连接异常
  // 且没有会话。那就只剩"客户端有没有处理这些数据"这一个问题了。
  // 包装 window.WebSocket，把生命周期的关键时刻和头几条消息回传到网关，
  // 就能直接看出：onmessage 到底触发没有、收到之后它做了什么。
  //
  // 注意：prototype 直接共用原生那份，所以 instanceof 依然成立。
  // ── WebSocket 仪表（2026-10-05 加）──────────────────────────────
  // 为什么：网关侧已经证明通道健康、基线数据也到了客户端；但 UI 仍报连接异常
  // 且没有会话。那就只剩"客户端有没有处理这些数据"这一个问题了。
  // 包装 window.WebSocket，把生命周期的关键时刻和头几条消息回传到网关，
  // 就能直接看出：onmessage 到底触发没有、收到之后它做了什么。
  //
  // 注意：prototype 直接共用原生那份，所以 instanceof 依然成立。
  var NativeWebSocket = window.WebSocket;
  if (typeof NativeWebSocket === 'function') {
    var Instrumented = function (url, protocols) {
      var socket = arguments.length > 1
        ? new NativeWebSocket(url, protocols)
        : new NativeWebSocket(url);
      try {
        send('ws', 'new ' + url);
        // ── readyState 诊断 + 规范对齐修正（2026-10-05 加）───────────────
        //
        // 怀疑：ArkWeb 可能在 readyState 仍是 CONNECTING(0) 的时候就触发 open 事件。
        // 这不影响大多数代码，但 DSH 的 mux 客户端判断"socket 能不能用"靠的正是
        // readyState === WebSocket.OPEN（见 packages/api/gateway/src/client/stream-client.ts
        // 里 RemoteStreamMuxClient.waitForSocket 的实现）。
        //
        // 后果与实测现象吻合：第一条流 workspace/follow 走的是"等 open 事件"的路径，
        // 能拿到 socket；紧接着 $events 来问的时候，this.socket 已经赋值、readyState
        // 却还是 0，于是它去排队等一个再也不会来的 open 事件 —— 永远挂着、不报错、
        // 不发帧。这正是日志里看到的样子。
        //
        // 这里做两件事：
        //   1) 把 open 触发时的真实 readyState 报回来（直接证实或否掉这个怀疑）
        //   2) 在实例上定义一个自己的 readyState getter：一旦 open 来过且尚未 close，
        //      就按规范报 1(OPEN)。原生本来就正确的话，这一步没有副作用。
        var readyStateGetter = Object.getOwnPropertyDescriptor(
          NativeWebSocket.prototype, 'readyState'
        );
        var openSeen = false;
        var closedSeen = false;
        var readRealReadyState = function () {
          if (readyStateGetter && typeof readyStateGetter.get === 'function') {
            return readyStateGetter.get.call(socket);
          }
          return -1;
        };
        var overrideOk = false;
        try {
          Object.defineProperty(socket, 'readyState', {
            configurable: true,
            get: function () {
              if (openSeen && !closedSeen) return 1;
              return readRealReadyState();
            },
          });
          overrideOk = true;
        } catch (e) { /* 定义不了就只做诊断 */ }
        socket.addEventListener('open', function () {
          openSeen = true;
          // 这一行是整个 readyState 怀疑的判据：
          // 原生 getter 报 0（CONNECTING）就说明 ArkWeb 在 readyState 还没变 OPEN
          // 的时候就触发了 open 事件；报 1 则说明怀疑不成立，得另找方向。
          // 「改写」那一项说明实例上的 readyState getter 有没有装上（装不上就没法修正）。
          send('ws.open', 'readyState=' + readRealReadyState()
            + '  实例改写=' + (overrideOk ? '已装' : '装不上')
            + '  url=' + url);
        });
        socket.addEventListener('close', function () { closedSeen = true; });
        // 出站消息也要记 —— 为什么（2026-10-05）：
        // 入站已经证明只有一条 baseline、始终没有 ready 帧；那就要看客户端到底
        // 有没有把 $events 的订阅发出去。协议层的 Pong 不走 WebSocket.send，
        // 所以这里只会记到**应用层**的发包，正是我们要看的。
        var sentCount = 0;
        var nativeSend = socket.send;
        socket.send = function (payload) {
          try {
            sentCount++;
            // 首次发包时把两种 readyState 都记下来：
            // 一个是客户端实际读到的（可能已被我们改写），一个是原生 getter 的真实值。
            // 两者不一致，就说明这个改写确实在替客户端兜住 ArkWeb 的时序问题。
            if (sentCount === 1) {
              send('ws.send.first', 'readyState(客户端所见)=' + socket.readyState
                + '  readyState(原生)=' + readRealReadyState());
            }
            if (sentCount <= 20) {
              var info;
              if (typeof payload === 'string') {
                // 关键：把出站帧的**完整内容**打出来（截断到 240 字符）。
                // 因为现在已知客户端只发了一个 type=open，下一步必须知道它开的是
                // 哪条 logical stream —— $events 才该收到 ready 帧。
                info = 'len=' + payload.length + ' 内容=' + payload.slice(0, 240);
              } else {
                info = '二进制 len=' + (payload && payload.byteLength ? payload.byteLength : '?');
              }
              send('ws.send', '#' + sentCount + ' ' + info);
            }
          } catch (e) { /* 仪表绝不能影响页面 */ }
          return nativeSend.apply(socket, arguments);
        };
        socket.addEventListener('close', function (event) {
          send('ws', 'close code=' + event.code + ' reason=' + event.reason +
            ' clean=' + event.wasClean);
        });
        socket.addEventListener('error', function () {
          send('ws', 'error ' + url);
        });
        var seen = 0;
        socket.addEventListener('message', function (event) {
          seen++;
          if (seen > 60) return;
          var data = event.data;
          var size;
          if (typeof data === 'string') size = data.length;
          else if (data && typeof data.byteLength === 'number') size = data.byteLength;
          else size = -1;

          // 关键：把每条消息的 type 打出来。
          // 依据官方架构文档（.agents/notes/.../session-history-and-event-transport.zh.md）：
          //   $events 逻辑流的第一帧必须是 { type: 'ready', clientId, host }，
          //   而 ConnectionController **只有收到 ready 才发布 connected**。
          //   所以"页面能加载、却没会话、UI 报连接异常"最可能的原因就是 ready 没到。
          // 只看前 120 字符是看不出这个的（之前的仪表就是这么写的，所以漏了）。
          var kind = '?';
          if (typeof data === 'string') {
            try {
              var parsed = JSON.parse(data);
              kind = parsed && parsed.type ? String(parsed.type) : '(无 type)';
              if (parsed && parsed.streamId) kind += ' stream=' + String(parsed.streamId).slice(0, 8);
              if (parsed && parsed.value && parsed.value.type) kind += ' value.type=' + String(parsed.value.type);
            } catch (e) {
              kind = 'JSON解析失败:' + e.message;
            }
          } else {
            kind = '二进制帧';
          }
          send('ws.message', '#' + seen + ' len=' + size + ' type=' + kind);
        });
      } catch (e) { /* 仪表绝不能影响页面 */ }
      return socket;
    };
    Instrumented.prototype = NativeWebSocket.prototype;
    Instrumented.CONNECTING = 0;
    Instrumented.OPEN = 1;
    Instrumented.CLOSING = 2;
    Instrumented.CLOSED = 3;
    try {
      window.WebSocket = Instrumented;
    } catch (e) { /* 有些环境不允许覆盖，那就没有仪表 */ }
  }

  // ── 本页第几次加载（计数器）────────────────────────────────────
  //
  // 为什么需要：怀疑 webview_flutter_ohos 会把同一个页面加载两次 —— 于是
  // **第一个页面被顶掉，但它那条 mux WebSocket 还挂在服务端上**，$events 永远
  // 不会来。表现正好是"第一次 ws 坏、后面全好，而且点重连（不重新加载页面）一定好"。
  //
  // 两条可疑路径（都读自插件源码，**均未验证**）：
  //   · WebViewHostApiImpl.ets:466-474  onControllerAttached 里设完 UA 会调 refresh()
  //   · OhosWebView.ets:37-41           ArkWeb 组件的 src 绑着活值，而插件另有 loadUrl
  //
  // 内存里的计数器活不过重载，所以用 sessionStorage —— 它在**整个标签生命周期**里
  // 都在，页面重载不会清掉。网关日志里的 [req] GET / 也能数，但分不清"两次文档
  // 请求"是 303 重定向还是真的加载了两次；这个计数器只认"这段 JS 真的执行了一遍"。
  //
  // 同时报 navigation 类型（navigate / reload / back_forward）：
  //   · 第二次是 reload          → 就是插件自己调了 refresh()
  //   · 第二次仍是 navigate      → 是"又发起了一次导航"（比如 src 被改）
  try {
    var loadKey = '__dsh_gateway_page_loads';
    var loads = parseInt(window.sessionStorage.getItem(loadKey) || '0', 10);
    if (!(loads >= 0)) loads = 0;
    loads += 1;
    window.sessionStorage.setItem(loadKey, String(loads));

    var navType = '(取不到)';
    try {
      var navEntries = window.performance.getEntriesByType('navigation');
      if (navEntries && navEntries.length > 0) navType = String(navEntries[0].type);
    } catch (e) { /* 取不到就算了 */ }

    send('pageLoad', '本页第 ' + loads + ' 次加载；导航类型=' + navType
      + '；href=' + String(location.href).slice(0, 160));
  } catch (e) {
    send('pageLoad', '计数失败: ' + (e && e.message ? e.message : String(e)));
  }

  // ── "这个页面到底活着没有"探针 ──────────────────────────────────
  //
  // 为什么加：当前最可疑的是 **ArkWeb 被嵌进 Flutter 平台视图时把页面的
  // 后台/空闲任务节流了**。
  // 依据（已实测）：同一台鸿蒙机器、同一个内核（ArkWeb 6.1.0.120 / Chrome 132）、
  // 同一个网关 —— **系统浏览器正常，App 里的 WebView 坏**；而电脑 Chrome 155 与
  // 安卓 WebView 114 都正常。所以剩下的变量只有"被谁嵌进去"。
  //
  // 这组数就是来量这件事的：定时器准不准、动画帧还在不在跑、空闲回调还在不在跑、
  // 页面被认为可见还是隐藏、视口尺寸是多少。
  //
  // ★ 关键：同一段探针在**系统浏览器**里也会跑 —— 这就是一次同内核的 A/B 对照。
  var alive = { raf: 0, idle: 0, idleRemain: -1, drift: -1, ticks: 0, online: 0, offline: 0 };
  try {
    // ── 网络状态（这一条是"最大嫌疑"）──────────────────────────────
    // DSH 客户端的连接循环开头有一道闸门：
    //   if (!networkAvailable && !immediateRetry) { 停在这里等网络 }
    // 而 networkAvailable 来自 navigator.onLine。**如果 ArkWeb 把它报成 false，
    // 连接循环就会按设计停在"离线"分支** —— 没有代际、没有 $events、没有报错、
    // 没有超时警告、页面还完全健康。而点重连会设 immediateRetry，正好绕过这道闸门。
    // 所以这里报：onLine 的当前值，以及 online / offline 事件各来过几次。
    try {
      window.addEventListener('online', function () { alive.online++; });
      window.addEventListener('offline', function () { alive.offline++; });
    } catch (e) { /* 挂不上就算了 */ }

    if (typeof requestAnimationFrame === 'function') {
      var rafTick = function () { alive.raf++; requestAnimationFrame(rafTick); };
      requestAnimationFrame(rafTick);
    }
    if (typeof requestIdleCallback === 'function') {
      var idleTick = function (deadline) {
        alive.idle++;
        try { alive.idleRemain = Math.round(deadline.timeRemaining()); } catch (e) { /* 取不到就算了 */ }
        requestIdleCallback(idleTick);
      };
      requestIdleCallback(idleTick);
    }
    var timerTick = function () {
      var startedAt = Date.now();
      setTimeout(function () {
        alive.drift = Date.now() - startedAt;
        alive.ticks++;
        timerTick();
      }, 1000);
    };
    timerTick();

    var aliveReports = 0;
    var aliveTimer = setInterval(function () {
      aliveReports++;
      if (aliveReports > 30) { clearInterval(aliveTimer); return; }
      var doc = document;
      var focus = (typeof doc.hasFocus === 'function') ? String(doc.hasFocus()) : '?';
      send('alive',
        '可见=' + String(doc.visibilityState)
        + ' 隐藏=' + String(doc.hidden)
        + ' 有焦点=' + focus
        + ' ★在线=' + String(navigator.onLine)
        + ' online事件=' + alive.online
        + ' offline事件=' + alive.offline
        + ' | 动画帧累计=' + alive.raf
        + ' 空闲回调累计=' + alive.idle
        + ' 空闲余量=' + alive.idleRemain
        + ' 定时器漂移=' + alive.drift + 'ms(第' + alive.ticks + '次)'
        + ' | 视口=' + window.innerWidth + 'x' + window.innerHeight
        + ' 文档=' + doc.documentElement.clientWidth + 'x' + doc.documentElement.clientHeight);
    }, 2000);
  } catch (e) {
    send('alive', '探针装不上: ' + (e && e.message ? e.message : String(e)));
  }

  // ── 能力探测（2026-10-05 加）────────────────────────────────────
  // 为什么：网关侧已证明通道健康、载荷完整且合法（len=6910 JSON_OK）、
  // 客户端的 onmessage 也触发了，但之后它什么都不做、UI 报连接异常 ——
  // 说明失败被它自己的 try/catch 吞了，看不到报错。
  // 那就反过来：让页面把"它依赖的那些能力到底能不能用"报回来。
  // 哪一项抛错，答案就在哪一项。
  function probe(name, run) {
    try {
      send('probe', name + ' = ' + run());
    } catch (error) {
      send('probe', name + ' 抛错: ' + (error && error.message ? error.message : String(error)));
    }
  }
  setTimeout(function () {
    probe('isSecureContext', function () { return String(window.isSecureContext); });
    probe('localStorage.setItem', function () {
      window.localStorage.setItem('__dsh_probe', '1');
      return 'OK';
    });
    probe('localStorage.getItem', function () {
      return String(window.localStorage.getItem('__dsh_probe'));
    });
    probe('sessionStorage.setItem', function () {
      window.sessionStorage.setItem('__dsh_probe', '1');
      return 'OK';
    });
    probe('indexedDB 存在', function () {
      return window.indexedDB ? 'OK' : '缺失';
    });
    probe('structuredClone 存在', function () {
      return typeof globalThis.structuredClone === 'function' ? 'OK' : '缺失';
    });
    probe('crypto.getRandomValues 存在', function () {
      return typeof window.crypto.getRandomValues === 'function' ? 'OK' : '缺失';
    });
    probe('Intl.DateTimeFormat', function () {
      return new Intl.DateTimeFormat('zh-CN').format(new Date(0));
    });
    probe('BigInt64Array', function () {
      return typeof BigInt64Array === 'function' ? 'OK' : '缺失';
    });
  }, 0);
  globalThis.__DSH_GATEWAY_SHIM__ = Object.assign(globalThis.__DSH_GATEWAY_SHIM__ || {}, {
    pageLogShim: true
  });
})();
</script>`

/** 注入到 `<head>` 之后的第一件事（保证早于页面自己的 defer 脚本）。 */
// ── 启动时自查注入脚本的语法（2026-10-05 加）──────────────────────
//
// 为什么必须放在这儿：这几段垫片都是**模板字符串**，所以
//   · 注释里写反引号 → 直接把字符串截断 → gateway.js 自己语法就错了；
//   · 注释里写反斜杠转义（换行、正则空白之类） → 反斜杠被模板字符串吃掉，
//     gateway.js 依然能正常加载，**只有注入到页面之后才失效** ——
//     症状是"页面一条日志都没有"，看起来像回传通道坏了，极难定位。
// 用 new Function 只编译不执行，能在起服务之前把这两类都挡下来。
// （这个自查是因为同一类错误连栽了三次才补上的：靠人自觉显然不行。）
for (const [shimName, shimSource] of [
  ['PAGE_LOG_SHIM', PAGE_LOG_SHIM],
  ['CLIENT_SHIM', CLIENT_SHIM],
  ['MOBILE_ENTER_SHIM', MOBILE_ENTER_SHIM],
  ['KEYBOARD_INSET_SHIM', KEYBOARD_INSET_SHIM],
]) {
  const shimBody = shimSource.replace(/<\/?script[^>]*>/gi, '\n')
  try {
    new Function(shimBody)
  } catch (error) {
    throw new Error(
      '注入脚本 ' + shimName + ' 语法错误：' + error.message
        + '（多半是注释里出现了反引号或反斜杠转义）',
    )
  }
}

function injectClientShim(html) {
  // 空模式（2026-10-05）：完全不注入，纯透明转发。
  //
  // 为什么需要：鸿蒙上客户端的 $events（以及 session/control）从来没被打开过，
  // 而垫片**从第一版起就一直注入在页面里**，却从来没做过"不注入"的对照 ——
  // 也就是说"是我的注入弄坏了插件的加载"这条一直没被排除。
  // 打开空模式后看不到 [page] 日志了，但网关侧的**字节数**仍是硬证据：
  // 客户端→上游 3 秒时约 117 字节 = 只发了一条 open；若有 400~600 字节，
  // 说明 5 条 open 都发出去了，那问题就在垫片。
  // 用环境变量打开，避免改代码。
  //
  // ⚠️ 这里必须打一行日志：上一次做空模式对照时，页面其实**仍在跑旧垫片**
  //（日志里照样有 [page] ws: new），于是那次对照是无效的、却没人发现。
  // 每个响应都打一行，才能确认空模式真的生效了。
  if (process.env.DSH_GATEWAY_BARE === '1') {
    // 注意：这里是**模块级函数**，拿不到 createGateway 的 logger。
    // 之前写成 logger.warn 直接把网关弄崩了（ReferenceError），
    // 而症状是客户端报 "Connection closed before full header was received" ——
    // 看起来像网络问题，其实是服务端自己挂了。用 console 输出到同一个日志文件。
    console.log('[shim] BARE 模式生效：本次页面 HTML 未注入任何东西')
    return html
  }

  const open = /<head(?:\s[^>]*)?>/i.exec(html)
  if (open === null) return html
  const at = open.index + open[0].length
  // 只注入这三段。键盘垫片（KEYBOARD_INSET_SHIM）已停用 —— 见它定义处说明。
  // PAGE_LOG_SHIM 放最前，这样其它垫片和页面自己的报错都能被它捕获。
  return (
    html.slice(0, at) + PAGE_LOG_SHIM + CLIENT_SHIM + MOBILE_ENTER_SHIM + html.slice(at)
  )
}

/**
 * 创建网关（不自动监听）。
 *
 * @param options.password      网关密码。空 / 非字符串 → 直接抛错（失败关闭）。
 * @param options.targetPort    上游 DSH Web 端口，数字或返回数字的函数。
 * @param options.resolveToken  返回「当前进程的启动 token」；拿不到就返回 undefined。
 *                              只有根请求会用到它。
 * @param options.host          监听地址，默认 0.0.0.0。
 * @param options.port          监听端口，默认 8080。
 * @param options.sessionDays   登录后 cookie 有效期，默认 30 天。
 * @param options.logger        日志出口，默认 console。
 */
export function createGateway(options) {
  const {
    password,
    targetPort,
    resolveToken = () => undefined,
    host = '0.0.0.0',
    port = 8080,
    sessionDays = 30,
    logger: rawLogger = console,
    /**
     * 客户端每次**成功换到 cookie** 时回调一次，参数 { address, platform, userAgent }。
     * 插件（dsh-webview-remote-server）用它写连接历史。可选，不传就是没有。
     * 回调抛错绝不影响这次认证 —— 记历史失败不该让人连不上。
     */
    onSession,
  } = options ?? {}

  // ── 给每条日志加时间戳（本轮加）──────────────────────────────────
  // 为什么必须有：在此之前整份日志**没有任何时间信息**，只能靠行号顺序推时序。
  // 而 "[page]" 那些行是页面异步回传的（sendBeacon / fetch），它的到达顺序和
  // "[ws]" 那些同步日志的先后**根本不可靠** —— 本项目已经因此误判过。
  // 放在唯一的出口上加前缀，所有调用点一行都不用改。
  const stampOf = (date) => {
    const pad = (value, width) => String(value).padStart(width, '0')
    return pad(date.getHours(), 2) + ':' + pad(date.getMinutes(), 2) + ':'
      + pad(date.getSeconds(), 2) + '.' + pad(date.getMilliseconds(), 3)
  }
  const withTimestamp = (sink) => {
    const wrap = (name) => {
      const fn = sink?.[name]
      if (typeof fn !== 'function') return undefined
      return (...args) => fn.call(sink, '[' + stampOf(new Date()) + ']', ...args)
    }
    return {
      info: wrap('info'),
      warn: wrap('warn'),
      error: wrap('error'),
      debug: wrap('debug'),
      log: wrap('log'),
    }
  }
  const logger = withTimestamp(rawLogger)

  if (typeof password !== 'string' || password === '') {
    throw new Error(
      'dsh-remote-gateway: 拒绝以空密码启动。本网关把 DSH 的 Origin 围栏对已认证流量失效了，' +
        '密码就是唯一的安全边界 —— 空密码等于把「在本机执行任意命令」的能力开放给整个网络。',
    )
  }

  const signer = makeSigner(password, sessionDays)
  const port_ = () => (typeof targetPort === 'function' ? targetPort() : targetPort)

  /** 已升级（WebSocket）的客户端 socket，关服务时要显式销毁。 */
  const upgraded = new Set()

  const setCookieHeader = (value, maxAgeSeconds) =>
    `${GATEWAY_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`

  /**
   * 从**请求头**里取客户端给的密码。
   *
   * **刻意不支持 URL 查询参数**：URL 会进浏览器历史、Referer、以及各种
   * 中间层日志，HTTPS 也救不了 —— 密码必须走头或 body。
   */
  function suppliedPassword(req) {
    const auth = req.headers.authorization
    if (typeof auth === 'string' && /^Bearer\s+/i.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim()
    const header = req.headers['x-gateway-password']
    if (typeof header === 'string' && header !== '') return header
    return undefined
  }

  function sendJson(res, status, body, extraHeaders) {
    const payload = Buffer.from(JSON.stringify(body), 'utf8')
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'content-length': String(payload.length),
      'cache-control': 'no-store',
      ...extraHeaders,
    })
    res.end(payload)
  }

  // ────────────────────────────────────────────────────────────
  // 把一次已鉴权的请求转发给上游
  // ────────────────────────────────────────────────────────────
  function proxyHttp(req, res, url) {
    const upstreamPort = port_()
    if (!Number.isInteger(upstreamPort)) {
      sendJson(res, 503, { error: 'gateway: upstream port unknown' })
      return
    }

    // ── token 注入规则（见 开发思路.md §3）──────────────────────
    // 只在两个条件同时成立时注入：
    //   1) 路径【恰好】是 '/'  —— DSH 的 token 交换只认这个路径，
    //      `/index.html` 带 token 会落到 401
    //   2) 客户端【没有】一张看起来还没过期的 `dsh-auth` cookie
    //
    // 为什么不能"每个请求都注入"：DSH 的 authorizeIndex 对「路径是 / 且带 token」
    // 的请求**一律 303 回 /**，从不返回首页 —— 于是
    //   每请求注入 → 303 → 跟随时又注入 → 再 303 → 无限重定向。
    //
    // 按本规则：
    //   没 cookie / 已过期 → 注入一次 → DSH 签新 cookie + 303
    //                      → 跟随请求已带有效 cookie → 不再注入 → 正常出首页
    let path = url.pathname + url.search
    if (
      url.pathname === '/' &&
      !url.searchParams.has('token') &&
      !hasLiveDshSession(req.headers.cookie)
    ) {
      const token = resolveToken()
      if (typeof token === 'string' && token !== '') {
        const withToken = new URL(url.href)
        withToken.searchParams.set('token', token)
        path = withToken.pathname + withToken.search
      } else {
        logger.warn?.(
          'dsh-remote-gateway: 拿不到当前进程的启动 token，根请求会以 401 返回；' +
            '请确认 connection 服务可用，或改用手动带 token 的 URL。',
        )
      }
    }

    // 文档请求要往 HTML 正文里注入垫片，所以不能让上游 gzip（否则得先解压）。
    // 只对文档这么做，静态资源照旧走 gzip。
    const isDocument = url.pathname === '/' || url.pathname.endsWith('/index.html')
    const headers = upstreamHeaders(req.headers, upstreamPort)
    if (isDocument) headers['accept-encoding'] = 'identity'

    // ── 请求日志（诊断用，2026-10-01 加）────────────────────────
    // 为什么需要：鸿蒙上 WebView 到底请求了什么、有没有带上会话 cookie，
    // **在设备侧看不到** —— Dart 的 debugPrint 不进 hilog（实测）。
    // 把网关这一步记下来，就能直接区分两类完全不同的故障：
    //   · gw=无  → 客户端根本没带上我们的 cookie → 会拿到 404 空页
    //   · gw=有 但页面仍不对 → 那是客户端那边的问题（比如#root 守卫误判）
    // ⚠️ 只记路径，**不记 token 值**（日志也是会被人看到的）。
    // /plugins/ 的完整 URL（含查询串）必须打出来 —— 每个插件是一个独立 URL，
    // 只看 pathname 会把它们全看成同一个 /plugins/，于是"某个插件 404 了"这种
    // 事在日志里完全看不出来（我前面就是这么被误导的）。
    const loggedPath = url.pathname.startsWith('/plugins/')
      ? url.pathname + url.search
      : url.pathname
    logger.info?.(
      `[req] ${req.method} ${loggedPath} ` +
        `gw=${parseCookies(req.headers.cookie)[GATEWAY_COOKIE] ? '有' : '无'} ` +
        `dsh会话=${hasLiveDshSession(req.headers.cookie) ? '有' : '无'} ` +
        `token=${url.searchParams.has('token') || path.includes('token=') ? '注入' : '未注入'} ` +
        `文档=${isDocument ? '是' : '否'}`,
    )

    // 诊断（2026-10-05）：/plugins/ 是**客户端 Remote 插件的加载入口**，
    // 而它间歇性返回 404 —— 那就会导致 $events 从没被打开、UI 永远"连接异常"。
    // 这里把这个请求的关键头和响应的缓存头都记下来，好和电脑上的正常请求对比。
    const isPluginsPath = url.pathname === '/plugins/' || url.pathname.startsWith('/plugins/')

    const upstream = http.request({
      host: LOOPBACK,
      port: upstreamPort,
      method: req.method,
      path,
      headers,
    })

    upstream.on('response', (upRes) => {
      const contentType = String(upRes.headers['content-type'] ?? '')
      logger.info?.(
        `[res] ${upRes.statusCode} ${url.pathname} type=${contentType === '' ? '(无)' : contentType}`,
      )

      // 页面 HTML 发出去了 → 进入启动窗口，接下来的 mux 升级会等零件装好。
      if (isDocument && req.method === 'GET') {
        lastIndexServedAt = Date.now()
        logger.info?.(
          '[ws] 已发出页面 HTML → 记下启动时刻；此后的 mux 升级是否先压住、压多久，'
            + '取决于 MUX_WARMUP_WINDOW_MS（当前值见该常量，0 = 不压）',
        )
      }
      if (isPluginsPath) {
        logger.warn?.(
          `[plugins] ${url.pathname}${url.search} ` +
            `accept=${req.headers.accept ?? '(无)'} ` +
            `sec-fetch-dest=${req.headers['sec-fetch-dest'] ?? '(无)'} ` +
            `referer=${req.headers.referer ?? '(无)'} ` +
            `origin=${req.headers.origin ?? '(无)'} ` +
            `|| 响应 ${upRes.statusCode} cache-control=${upRes.headers['cache-control'] ?? '(无)'} ` +
            `etag=${upRes.headers.etag ?? '(无)'}`,
        )

        // 强制 /plugins/ 不缓存（2026-10-05 加）。
        //
        // 为什么：上游给它的响应头是
        //   cache-control: public, max-age=31536000, immutable
        // —— 一年、而且永不校验。可这个 URL **没有内容哈希**：插件集合一变
        //（装 / 卸插件），客户端手里那份就是旧的。旧的插件包对不上当前的 Host →
        // 客户端 Remote / Session 插件起不来 → `$events` 与 `session/control`
        // 永远不开 → UI"连接异常"；而 workspace/follow 在主 bundle 里，不受影响。
        //
        // 实测旁证：某次加载里页面**完全没有请求** /plugins/（直接吃了一年缓存），
        // 而同一次 `$events` 依旧没开。
        //
        // 这里直接改上游 headers —— downstreamHeaders 在这之后才计算，所以生效。
        delete upRes.headers['cache-control']
        delete upRes.headers.etag
        delete upRes.headers['last-modified']
        delete upRes.headers.expires
        upRes.headers['cache-control'] = 'no-store'
        logger.warn?.('[plugins] 已改写为 cache-control: no-store（强制每次重新取）')
      }

      if (contentType.startsWith('text/html')) {
        // HTML 只有几 KB，整段缓冲后注入垫片再发出。
        // ⚠️ 这条分支【绝不能】用在 SSE / 流式响应上 —— 所以只认 text/html。
        const chunks = []
        upRes.on('data', (chunk) => chunks.push(chunk))
        upRes.on('end', () => {
          // 注入失败绝不能把网关弄崩。
          // 曾经因为注入函数里一个 logger 引用错误，网关每次发页面就退出，
          // 客户端那边看到的是 "Connection closed before full header was received" ——
          // 完全联想不到是服务端自己挂了。失败就原样返回页面。
          const rawHtml = Buffer.concat(chunks).toString('utf8')
          let injectedHtml = rawHtml
          try {
            injectedHtml = injectClientShim(rawHtml)
          } catch (error) {
            logger.warn?.(`[shim] 注入失败，原样返回页面：${error.message}`)
          }
          const body = Buffer.from(injectedHtml, 'utf8')
          const outHeaders = downstreamHeaders(upRes.headers, upstreamPort)
          // 注入后长度变了，而且我们强制过 identity，所以这两个都要重算/去掉
          delete outHeaders['content-encoding']
          outHeaders['content-length'] = String(body.length)
          res.writeHead(upRes.statusCode ?? 502, outHeaders)
          res.end(body)
        })
        upRes.on('error', () => res.destroy())
        return
      }

      res.writeHead(upRes.statusCode ?? 502, downstreamHeaders(upRes.headers, upstreamPort))
      // SSE 必须尽快把响应头推出去，否则客户端会以为请求还卡着。
      res.flushHeaders?.()
      upRes.pipe(res)
      upRes.on('error', () => res.destroy())
    })

    upstream.on('error', (error) => {
      // 上游连不上，最常见的唯一原因就是「**DSH 本体没在运行**」。
      // 单独把它说清楚：否则客户端只拿到一个笼统的 502，用户完全无从下手
      //（实测症状：服务端没起来时，客户端那边一直转圈、看不出究竟）。
      const refused = error.code === 'ECONNREFUSED'
      const message = refused
        ? `上游 DSH 没在运行（${LOOPBACK}:${upstreamPort} 拒绝连接）—— 请先把 DSH 本体起起来`
        : `上游出错：${error.message}`
      logger.warn?.(`[!] ${url.pathname} → ${message}`)
      if (!res.headersSent) {
        sendJson(res, 502, { error: `gateway: ${message}` })
      } else {
        res.destroy()
      }
    })

    // 客户端断开（手机锁屏、切后台）时立刻掐掉上游，别把连接挂着。
    res.on('close', () => upstream.destroy())

    // 请求体流式转发：上传大文件不会整个读进内存。
    req.pipe(upstream)
  }

  // ────────────────────────────────────────────────────────────
  // 转发 WebSocket 升级
  // 【已读码】DSH 的 /api/remote.mux 是一条 WebSocket（Remote 多路复用 + 2s 心跳，
  // 由 dsh-api-gateway 经 registerUpgrade 注册）。不转发它，手机上 UI 的
  // 流/事件会静默失效 —— 页面能打开，但永远不更新。
  // ────────────────────────────────────────────────────────────
  // ── "等零件装好再连接"所需的状态（2026-10-05）────────────────────
  //
  // 背景（本轮实测）：第一次连接时，客户端的 `$events`（连接代际的唯一来源）
  // 根本没轮到发出去 —— 它必须等客户端 loader 就绪后才 start()；而同一条 mux
  // WebSocket 在插件构造时就建好了，所以 `workspace/follow` 先出去了、
  // `$events` 没有。表现就是"第一次连接异常、手动点重连才好"。
  //
  // 修法按用户说的办：**等所有零件装好再连接**。
  // 网关看不见客户端的 loader，所以用"页面启动窗口"近似：把**页面刚发出去之后
  // 这段窗口内**的第一次 mux 升级压住，等窗口过去再放行。
  // 窗口之外的升级（真正的重连）一律不拦。
  /** 最近一次把页面 HTML 发给客户端的时刻。 */
  let lastIndexServedAt = 0
  /**
   * 页面启动窗口：这段时间内的 mux 升级会被压住。
   *
   * 2026-10-05 重新启用，并把 3 秒改成 8 秒。
   *
   * 为什么之前那次（3 秒）没用：那道闸门只压住了**升级请求**，于是 socket 建立
   * 和连接循环的启动被**同时**往后推，两者的先后关系丝毫没变 —— 等于没做。
   * 真正要拉开的是「socket 建立」和「连接循环启动（$events 由它发出）」之间的时间差。
   *
   * 而连接循环卡在 `ctx.get('loader').await()` 后面（源码：
   * packages/api/gateway/src/client/index.ts），从实测日志看它明显晚于 3 秒，
   * 所以 3 秒的窗口根本不够：socket 照样先开，第一条流照样是 workspace/follow。
   *
   * 用户从一开始的判断就是对的：这是加载时机问题 —— 安卓加载快、
   * 或者顺序不同，所以它从来不出事。
   *
   * ⚠️ 注意：这是网关侧的兜法，只在**页面刚发出去的窗口内**生效；
   * 窗口之外的升级（真正的重连）一律不拦。上限见 MUX_WARMUP_MAX_MS。
   */
  // ⚠️ 已停用（对照实验）：置 0 = **不压任何升级**。
  //
  // 为什么停用：这个机制是整段代码里**唯一一个"只针对页面加载后第一次 mux 升级"
  // 下手的地方**，而鸿蒙 ArkWeb 上的症状恰好是"第一次 ws 坏、后面全好" ——
  // 两者形状完全一致，所以必须先做这一次最小对照把它排除掉。
  //
  // 【待验证】置 0 之后鸿蒙上第一次 ws 是否恢复正常：
  //   · 恢复正常 → 这个现象是"压"出来的（ArkWeb 的握手等不了这么久），
  //     那就把它改成"只在确认客户端还没热身时才压，且压的时长要短"；
  //   · 照旧坏   → 与本机制无关，恢复成 8000，改走别的路。
  const MUX_WARMUP_WINDOW_MS = 0
  /** 压住的上限；超时就照常放行，绝不把连接掐死。 */
  const MUX_WARMUP_MAX_MS = 15000

  // ── 定点规避的参数（2026-10-05）────────────────────────────────
  //
  // 鸿蒙 ArkWeb 上，DSH 客户端有时不会发出 `$events` 那条逻辑流 ——
  // 它是唯一能把连接标记为"已建立"的流。此时客户端只发一条
  // workspace/follow，上行字节数停在 120 左右，之后只剩每 3 秒的 Pong；
  // 界面就一直"连接异常"、也没有会话。而**手动点一次"重连"之后一定能建立**
  //（手机端多次实测，日志里有完整帧序列）。
  //
  // 所以这里替用户点那一下：mux 建立后等 MUX_HEALTH_CHECK_MS，
  // 若客户端上行仍低于 MUX_HEALTH_MIN_BYTES（断言它没开出逻辑流），
  // 就主动断开这条 socket，让客户端走它自己那条已验证有效的重连路径。
  //
  // 阈值选 300 字节的理由：正常客户端在头一秒内就会发出多条 open
  //（$events 108 + session/control 116 + workspace/follow 117 + session/follow 300 …），
  // 实测远超此值；出问题时只有 ~120 字节。
  // ⚠️ 已停用（2026-10-05 收工）：置 0 = 不做这个健康检查。
  //
  // 停用原因：判据（6 秒内上行 < 300 字节就断开）**有可能误伤健康客户端** ——
  // 安卓正常时头几秒也可能只发出 workspace/follow(117) + $events(108) ≈ 225 字节，
  // 还没轮到 session/control。而它本身的效果**从未验证过**（收工前最后一轮没跑完）。
  // 用一个未验证、且可能掐断好连接的机制去换一个未验证的收益，不划算。
  // 要重新启用：把 MUX_HEALTH_CHECK_MS 设回 6000，并先按实测把阈值调准。
  const MUX_HEALTH_CHECK_MS = 0
  const MUX_HEALTH_MIN_BYTES = 300

  function proxyUpgrade(req, socket, head, url) {
    const upstreamPort = port_()
    if (!Number.isInteger(upstreamPort)) {
      socket.destroy()
      return
    }
    if (!signer.verify(parseCookies(req.headers.cookie)[GATEWAY_COOKIE])) {
      logger.warn?.(`[ws] 401 ${url.pathname} ← 升级请求没带网关 cookie`)
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }

    // ── 等零件装好再连接（2026-10-05 修）────────────────────────────
    //
    // 依据（实测日志）：第一次加载时客户端在 mux 上**只发了 workspace/follow**，
    // `$events` 根本没发。源码里两条路不同步：
    //   · mux：插件构造时就 this.streams.start()          → 早
    //   · $events：必须等 ctx.get('loader').await() 之后 start() → 晚
    // 于是第一次连接总是缺 `$events`，客户端自己判 connection lost。
    //
    // 网关看不见 loader，所以用"页面启动窗口"近似：页面刚发出去这段时间内的
    // 第一次 mux 升级先压住，等窗口过去再放行。窗口之外（真正的重连）不拦。
    // 上限 MUX_WARMUP_MAX_MS，超时照常放行，绝不把连接掐死。
    const sincePageServed = lastIndexServedAt === 0 ? -1 : Date.now() - lastIndexServedAt
    if (url.pathname === '/api/remote.mux'
      && sincePageServed >= 0
      && sincePageServed < MUX_WARMUP_WINDOW_MS) {
      if (socket.__muxWaitStart === undefined) socket.__muxWaitStart = Date.now()
      const waitedMs = Date.now() - socket.__muxWaitStart
      if (waitedMs < MUX_WARMUP_MAX_MS && !socket.destroyed) {
        if (!socket.__muxWaitLogged) {
          socket.__muxWaitLogged = true
          logger.info?.(
            `[ws] 页面才发出去 ${sincePageServed}ms，零件还没装好 —— 先压住这次 mux 升级`,
          )
        }
        setTimeout(() => proxyUpgrade(req, socket, head, url), 120)
        return
      }
      logger.warn?.('[ws] 等启动窗口超时，照常放行 mux 升级')
    }

    // ── 升级路径的日志（2026-10-02 加）────────────────────────────
    // 为什么单独加：DSH 的实时通道走 WebSocket 升级，而普通 HTTP 的日志
    // 覆盖不到它。上一轮"页面能打开、但 DSH 自己报连接失败"就是因为这条
    // 路径**完全没有日志**，查不到任何证据。只记路径和结果，不记 header
    // （header 里有 cookie）。
    const upgradePath = url.pathname
    logger.info?.(`[ws] 升级请求 ${req.method} ${upgradePath}`)

    const headers = upstreamHeaders(req.headers, upstreamPort)
    headers.connection = 'Upgrade'
    if (typeof req.headers.upgrade === 'string') headers.upgrade = req.headers.upgrade

    // 诊断（2026-10-05）：**去掉 WebSocket 扩展协商**，即不让它用
    // permessage-deflate 压缩。原因：压缩后通道里流的是二进制，首帧采样
    // 只能看到乱码，没法判断那 7KB 到底是什么。去掉之后帧内容是明文，
    // 一眼可读，也顺带排除"客户端解压环节出问题"这一类可能。
    // 副作用可忽略：压缩只省流量，而这里是局域网。
    delete headers['sec-websocket-extensions']

    const upstream = http.request({
      host: LOOPBACK,
      port: upstreamPort,
      method: req.method,
      path: url.pathname + url.search,
      headers,
    })

    // ── 把客户端"预发"的首帧转给上游（2026-10-05 修）────────────────
    // `head` 是客户端在**收到 101 之前**就跟着升级请求一起发出来的字节。
    // 早先这里完全没处理它 —— 我当时看了一眼，心想"WS 升级时 head 通常是空的"
    // 就放过了，这就是那个 bug。
    //
    // 症状与它是怎么对上的：DSH 的客户端在插件激活时立即连接 mux，并且
    // 把 $events 的订阅帧抢在握手之前发出去。head 被丢掉 → Host 收不到订阅
    // → 永远不回 `ready` 帧 → ConnectionController 永不发布 connected
    // → UI 显示"连接异常"；而手动重连时客户端已经热身，订阅帧在握手之后才发，
    // 所以就好了。安卓上时序不同，没抢发，所以从来没触发。
    upstream.on('finish', () => {
      if (head && head.length > 0) {
        logger.info?.(`[ws] 转发客户端预发首帧 ${head.length} 字节 → 上游`)
        upstream.socket.write(head)
      }
    })

    let settled = false
    upstream.on('upgrade', (upRes, upSocket, upHead) => {
      settled = true
      const openedAt = Date.now()
      logger.info?.(`[ws] ${upRes.statusCode} ${upgradePath} ← 上游同意升级，通道建立`)
      const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage ?? 'Switching Protocols'}`]
      const raw = upRes.rawHeaders
      for (let i = 0; i < raw.length; i += 2) lines.push(`${raw[i]}: ${raw[i + 1]}`)
      socket.write(lines.join('\r\n') + '\r\n\r\n')
      if (upHead?.length) socket.write(upHead)

      upgraded.add(socket)
      upgraded.add(upSocket)

      // ── 通道生命周期日志（2026-10-02 加）──────────────────────────
      // 为什么需要：升级**成功**（101）不等于通道能用。DSH 的实时通道可能
      // 建立之后立刻断开 —— 而"页面能加载、UI 却报连接异常"恰好长这样。
      // 记存活时长和双向字节数就能一眼区分：
      //   · 开了几十毫秒就关、字节数几乎为 0 → 协议/认证层被拒
      //   · 活了很久、字节数在涨             → 通道是好的，问题在别处
      // 注意：只加计数器，不消费数据 —— pipe 照常负责搬运。
      let toUpstream = 0
      let toClient = 0
      let sampledFirstFrame = false
      socket.on('data', (chunk) => { toUpstream += chunk.length })
      upSocket.on('data', (chunk) => {
        toClient += chunk.length
        // 只采样**第一帧**、最多 300 字节，而且只采一次。
        // 为什么：通道建立后 DSH 会先推一坨东西（实测约 7KB）——
        // 如果那是一帧错误，答案就在开头。只采一次是为了不把会话内容
        // 源源不断地写进日志。
        if (!sampledFirstFrame) {
          sampledFirstFrame = true
          const sample = chunk.slice(0, 300).toString('utf8').replace(/[\r\n\t]+/g, ' ')
          logger.warn?.(`[ws] 下行首帧样本（前 300 字节）: ${sample}`)
        }
      })

      // 周期性活动日志（2026-10-05 加）—— **这一条才是关键**。
      // 下面那条只在 close 时打；而我们现在遇到的恰恰是"通道一直开着"，
      // 于是那条永远不触发、等于没有数据。每 3 秒记一次就能直接看出：
      //   · 字节数一直是 0 → 通道建起来了但没人说话
      //   · 字节数在涨     → 通道正常收发，问题在 UI 侧
      let ticker = null

      const reportClose = (why) => {
        if (ticker !== null) clearInterval(ticker)
        logger.warn?.(
          `[ws] 关闭 ${upgradePath}（${why}）存活 ${Date.now() - openedAt}ms，` +
            `客户端→上游 ${toUpstream} 字节 / 上游→客户端 ${toClient} 字节`,
        )
      }
      socket.once('close', () => reportClose('客户端关闭'))
      upSocket.once('close', () => reportClose('上游关闭'))

      const drop = () => {
        upgraded.delete(socket)
        upgraded.delete(upSocket)
        upSocket.destroy()
        socket.destroy()
      }
      socket.on('close', () => upgraded.delete(socket))
      upSocket.on('close', () => upgraded.delete(upSocket))
      socket.on('error', drop)
      upSocket.on('error', drop)

      ticker = setInterval(() => {
        logger.info?.(
          `[ws] 活动 ${upgradePath} 存活 ${Math.round((Date.now() - openedAt) / 1000)}s，` +
            `客户端→上游 ${toUpstream} 字节 / 上游→客户端 ${toClient} 字节`,
        )
      }, 3000)
      ticker.unref?.()

      // 定点规避已停用（MUX_HEALTH_CHECK_MS = 0），见常量处的说明。
      if (upgradePath === '/api/remote.mux' && MUX_HEALTH_CHECK_MS > 0) {
        const healthTimer = setTimeout(() => {
          if (socket.destroyed || socket.writableEnded) return
          if (toUpstream >= MUX_HEALTH_MIN_BYTES) return
          logger.warn?.(
            `[ws] 规避：mux 建立 ${MUX_HEALTH_CHECK_MS}ms 后客户端只发了 ${toUpstream} 字节`,
          )
          logger.warn?.('[ws] 规避：判定它没开出连接流 → 主动断开，让它自己重连一次')
          socket.end()
        }, MUX_HEALTH_CHECK_MS)
        healthTimer.unref?.()
        socket.once('close', () => clearTimeout(healthTimer))
      }

      upSocket.pipe(socket)
      socket.pipe(upSocket)
    })

    // 上游没同意升级（比如它自己回了 401/403）→ 原样告诉客户端并断开。
    upstream.on('response', (upRes) => {
      if (settled) return
      settled = true
      logger.warn?.(`[ws] ${upRes.statusCode} ${upgradePath} ← 上游【拒绝】升级`)
      const lines = [`HTTP/1.1 ${upRes.statusCode} ${upRes.statusMessage ?? ''}`]
      for (const [name, value] of Object.entries(downstreamHeaders(upRes.headers, upstreamPort))) {
        if (Array.isArray(value)) for (const item of value) lines.push(`${name}: ${item}`)
        else lines.push(`${name}: ${value}`)
      }
      socket.write(lines.join('\r\n') + '\r\n\r\n')
      socket.destroy()
      upRes.resume()
    })

    upstream.on('error', () => {
      if (!settled) socket.destroy()
    })
    socket.on('error', () => upstream.destroy())

    if (head?.length) upstream.write(head)
    upstream.end()
  }

  // ────────────────────────────────────────────────────────────
  // HTTP 入口
  // ────────────────────────────────────────────────────────────
  const server = http.createServer((req, res) => {
    let url
    try {
      url = new URL(req.url ?? '/', 'http://gateway')
    } catch {
      sendJson(res, 400, { error: 'gateway: bad request url' })
      return
    }

    const done = (fn) => {
      try {
        fn()
      } catch (error) {
        logger.warn?.(`dsh-remote-gateway: ${error instanceof Error ? error.message : String(error)}`)
        if (!res.headersSent) sendJson(res, 500, { error: 'gateway: internal error' })
        else res.destroy()
      }
    }

    // ---- 网关自己的端点 ----
    // 密码换 cookie 的专用入口：客户端（App / curl）带 X-Gateway-Password 请求头
    // 打这里，拿一张 HttpOnly 的网关 cookie，之后交给 WebView。
    //
    // 为什么需要它：WebSocket 握手没法自定义请求头，而 App 在 WebView 的**初次导航**
    // 上加头又不一定被平台支持。走这个端点就与平台无关了。
    if (url.pathname === `${PREFIX}/session`) {
      done(() => {
        const given = suppliedPassword(req)
        if (given === undefined || !sameSecret(given, password)) {
          // 同样给空正文的 401，不留指纹。App 只读状态码。
          res.writeHead(401, { 'content-length': '0', 'cache-control': 'no-store' })
          res.end()
          return
        }
        res.writeHead(204, {
          'set-cookie': setCookieHeader(signer.issue(), sessionDays * 86400),
          'cache-control': 'no-store',
        })
        res.end()
        // 记一条接入记录。平台由客户端自己声明（App 会带 x-client-platform）；
        // 拿不到就留空 —— 不要去猜（Dart 的 HttpClient 默认 UA 既不是安卓也不是鸿蒙）。
        try {
          onSession?.({
            address: req.socket?.remoteAddress ?? '',
            platform: String(req.headers['x-client-platform'] ?? '').toLowerCase(),
            userAgent: req.headers['user-agent'] ?? '',
          })
        } catch {
          /* 记历史失败绝不能影响这次认证 */
        }
      })
      return
    }

    if (url.pathname === `${PREFIX}/health`) {
      done(() => sendJson(res, 200, { ok: true, gateway: 'dsh-remote-gateway' }))
      return
    }

    if (url.pathname === `${PREFIX}/logout`) {
      // 清掉网关会话。返回 204，**不重定向到任何页面** ——
      // 这个端口不给浏览器显示东西（见文件上方那段说明）。
      done(() =>
        res
          .writeHead(204, {
            'set-cookie': setCookieHeader('', 0),
            'cache-control': 'no-store',
          })
          .end(),
      )
      return
    }

    // ── 页面错误回传端点（垫片用，2026-10-05 加）────────────────────
    // 见 PAGE_LOG_SHIM 的说明：鸿蒙上看不到 WebView 内部报错，
    // 只能让页面主动发回来。要求带网关 cookie，避免变成任何人都能写的日志池。
    if (url.pathname === `${PREFIX}/log` && req.method === 'POST') {
      if (!signer.verify(parseCookies(req.headers.cookie)[GATEWAY_COOKIE])) {
        res.writeHead(401, { 'content-length': '0' }).end()
        return
      }
      const chunks = []
      let size = 0
      req.on('data', (chunk) => {
        size += chunk.length
        if (size <= 8192) chunks.push(chunk)
      })
      req.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8').replace(/[\r\n]+/g, ' ')
        logger.warn?.(`[page] ${text}`)
        done(() => res.writeHead(204, { 'content-length': '0' }).end())
      })
      return
    }

    if (url.pathname.startsWith(`${PREFIX}/`)) {
      done(() => sendJson(res, 404, { error: 'gateway: no such endpoint' }))
      return
    }

    // ---- 鉴权闸门 ----
    done(() => {
      let authed = signer.verify(parseCookies(req.headers.cookie)[GATEWAY_COOKIE])

      // 客户端的第一次请求可以直接带密码（Flutter 原生输入框用得上）：
      // 校验通过就顺手发一个会话 cookie，后续请求（资源、SSE、WebSocket）才带得上。
      if (!authed) {
        const given = suppliedPassword(req)
        if (given !== undefined && sameSecret(given, password)) {
          authed = true
          res.setHeader('set-cookie', setCookieHeader(signer.issue(), sessionDays * 86400))
        }
      }

      if (!authed) {
        // 无凭据 = **看起来这个路径根本不存在**。
        //
        // 【用户要求】这里返回 **404**，不是 401 ——
        //   401 本身就在说"这儿有个需要认证的东西"，那也是一条指纹；
        //   404 则和"随便哪个 HTTP 服务上不存在的路径"长得一模一样。
        // 正文同样为空。
        //
        // 注意：`/__gateway/session` 那处**仍然返回 401** —— App 靠它区分
        // "密码不对"。那条路径要猜（`__gateway/session`），不构成入口指纹。
        //
        // 【用户原则】降低可发现性是有效的防御层次，但它**买的是时间、不是边界**：
        // 一旦被找到这层就归零，所以密码强度与传输加密（TLS）仍然必须到位。
        res.writeHead(404, { 'content-length': '0', 'cache-control': 'no-store' })
        res.end()
        return
      }

      proxyHttp(req, res, url)
    })
  })

  server.on('upgrade', (req, socket, head) => {
    let url
    try {
      url = new URL(req.url ?? '/', 'http://gateway')
    } catch {
      socket.destroy()
      return
    }
    proxyUpgrade(req, socket, head, url)
  })

  return {
    server,
    get port() {
      return server.address()?.port
    },
    /** 开始监听；listen 失败会 reject（端口占用等）。 */
    listen() {
      return new Promise((resolve, reject) => {
        const onError = (error) => reject(error)
        server.once('error', onError)
        server.listen(port, host, () => {
          server.off('error', onError)
          server.on('error', (error) => logger.error?.(error))
          resolve(server.address()?.port)
        })
      })
    },
    /** 关服务：先停新连接，再销毁所有已升级的长连接。 */
    async close() {
      const closed = new Promise((resolve) => server.close(() => resolve()))
      server.closeAllConnections?.()
      for (const socket of upgraded) socket.destroy()
      upgraded.clear()
      await closed
    },
  }
}
