// ============================================================
// dsh-webview-remote-server —— 宿主半区
//
// 把原来那个"独立跑的 node 网关脚本"收进 DSH 成为一个插件：
//   · token 不再落盘 —— 直接问 connection.authenticatedUrl() 现取
//   · 密码 / 端口 存 $DSH_HOME/webview-remote-server/config.json（明文，本机文件）
//   · 记录连接历史（谁、什么时候、安卓还是鸿蒙）
//   · 给客户端半区（设置页那一栏）开一条 RPC 通道
//
// ── 为什么不再需要 dsh-web-url.txt ──────────────────────────────
// token 是进程级随机、只在内存里。原来那个文件是"把 token 抄出来给另一个进程用"，
// 现在网关和 token 在同一个进程里，直接现取即可 —— 顺带消灭了"文件过期 / 读到旧
// token"这一整类问题（DSH 每次重启 token 都会换）。
//
// ── 远程客户端看到什么 ─────────────────────────────────────────
// 客户端半区用 ctx.remote.$host.isLoopback 判断：远程时那一栏不渲染，
// 就算点进去也只有一句"仅本机可用"。跟 DSH 自己保护设置页的做法一致。
//
// ── 已实测（2026-10-15）─────────────────────────────────────────
//   · 在 DSH 里真实装载：设置页那一栏出现、能存住密码、能起监听
//   · 手机（鸿蒙 ArkWeb）连上：认证 → 记历史 → 页面正常加载
//     —— 也就是"token 现取"这条路是通的（原来靠落盘的 token 文件）
//   · 非本机打开时那一栏只显示一句"不可用"，不渲染配置面板
//   · 首次安装免重启；换版本重装必须重启 DSH（宿主半区改动要重启）
// ============================================================

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { createGateway } from './gateway.js'

/** 插件名（cordis 用）；RPC 通道名与它同源，便于一眼对上。 */
const PLUGIN_NAME = 'webview-remote-server'
/** RPC 通道：客户端半区用同一个常量来 call。 */
const CHANNEL = '/webview-remote-server'
/** 数据目录名（$DSH_HOME 下）。 */
const DIR_NAME = 'webview-remote-server'

/** 默认配置。password 为空 = 不启动监听（**默认不暴露任何端口**）。 */
const DEFAULT_CONFIG = {
  password: '',
  port: 8080,
  /** 连接历史最多留多少条。 */
  historyLimit: 200,
}

// ────────────────────────────────────────────────────────────
// 路径
// ────────────────────────────────────────────────────────────

/** DSH home：优先环境变量，否则 ~/.dsh（与 dsh-home-paths 的习惯一致）。 */
function homeDir() {
  return process.env.DSH_HOME ?? join(homedir(), '.dsh')
}
function dataDir() {
  return join(homeDir(), DIR_NAME)
}
function configPath() {
  return join(dataDir(), 'config.json')
}
function historyPath() {
  return join(dataDir(), 'history.json')
}

// ────────────────────────────────────────────────────────────
// 配置读写
// ────────────────────────────────────────────────────────────

function readJson(file, fallback) {
  try {
    if (!existsSync(file)) return fallback
    const text = readFileSync(file, 'utf8')
    const parsed = JSON.parse(text)
    return parsed !== null && typeof parsed === 'object' ? parsed : fallback
  } catch {
    return fallback
  }
}

/** 原子写：先写 .tmp 再 rename，避免只写了半个文件。 */
function writeJson(file, value) {
  mkdirSync(dataDir(), { recursive: true })
  const tmp = file + '.tmp'
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', 'utf8')
  renameSync(tmp, file)
}

function readConfig() {
  const raw = readJson(configPath(), {})
  const port = Number(raw.port)
  return {
    password: typeof raw.password === 'string' ? raw.password : DEFAULT_CONFIG.password,
    port: Number.isInteger(port) && port > 0 && port <= 65535 ? port : DEFAULT_CONFIG.port,
    historyLimit: Number.isInteger(raw.historyLimit) && raw.historyLimit > 0
      ? raw.historyLimit
      : DEFAULT_CONFIG.historyLimit,
  }
}

function writeConfig(next) {
  writeJson(configPath(), next)
}

// ────────────────────────────────────────────────────────────
// 连接历史
// ────────────────────────────────────────────────────────────

function readHistory() {
  const list = readJson(historyPath(), [])
  return Array.isArray(list) ? list : []
}

/**
 * 追加一条连接记录。
 * 字段：at（毫秒时间戳）、address（来源地址）、platform（android / ohos / 空）、userAgent
 */
function appendHistory(entry, limit) {
  try {
    const list = readHistory()
    list.push(entry)
    const kept = list.length > limit ? list.slice(list.length - limit) : list
    writeJson(historyPath(), kept)
  } catch {
    /* 记历史失败绝不能影响连接本身 */
  }
}

// ────────────────────────────────────────────────────────────
// 工具
// ────────────────────────────────────────────────────────────

/** 取服务：优先 ctx.get()，退回属性访问，两条路都试过再放弃（同 dsh-print-web-url）。 */
function service(context, name) {
  try {
    const viaGet = typeof context.get === 'function' ? context.get(name) : undefined
    if (viaGet !== undefined) return viaGet
  } catch {
    /* 回落属性访问 */
  }
  return context[name]
}

function ok(value) {
  return { ok: true, value }
}
function fail(code, message) {
  return { ok: false, error: { code, message, details: {} } }
}

// ────────────────────────────────────────────────────────────
// 主体
// ────────────────────────────────────────────────────────────

/**
 * 起一次插件。
 * @param {object} ctx - 插件自己的 context（用于 logger / effect）
 * @param {object} webCtx - 注入进来的 web context（connection / webServer 都在这儿）
 */
function boot(ctx, webCtx) {
  const logger = ctx.logger ?? console

  let config = readConfig()
  /** 当前监听中的网关实例；未配密码时为 undefined。 */
  let gate
  let listeningPort

  /**
   * token 提供者：**每次根请求现取**（DSH 重启换 token 也不用重启本插件）。
   * 返回 undefined 表示这一刻拿不到 —— 网关会当作"没有 token"处理。
   */
  function resolveToken() {
    const connection = service(webCtx, 'connection')
    const webServer = service(webCtx, 'webServer')
    const dshPort = webServer?.port
    if (!Number.isInteger(dshPort)) return undefined
    if (typeof connection?.authenticatedUrl !== 'function') return undefined
    try {
      // 只要一个带 token 的 URL；authority 用 loopback 就够（token 与 authority 无关）
      const url = connection.authenticatedUrl(`http://127.0.0.1:${dshPort}`)
      return new URL(url).searchParams.get('token') ?? undefined
    } catch {
      return undefined
    }
  }

  function upstreamPort() {
    return service(webCtx, 'webServer')?.port
  }

  /** 起监听。没配密码就**什么都不做** —— 默认不暴露端口。 */
  async function startGateway() {
    if (gate !== undefined) return
    if (typeof config.password !== 'string' || config.password === '') {
      logger.info?.(`[${PLUGIN_NAME}] 还没配密码，未启动监听（去设置页「WebView 远程」里设置）`)
      return
    }
    const targetPort = upstreamPort()
    if (!Number.isInteger(targetPort)) {
      logger.warn?.(`[${PLUGIN_NAME}] webServer.port 还不可用，这次不起监听`)
      return
    }
    const instance = createGateway({
      password: config.password,
      targetPort,
      resolveToken,
      host: '0.0.0.0',
      port: config.port,
      logger,
      // 客户端过了鉴权就记一条 —— 由网关在 /__gateway/session 成功时回调
      onSession: (meta) => {
        appendHistory(
          {
            at: Date.now(),
            address: meta?.address ?? '',
            platform: meta?.platform ?? '',
            userAgent: String(meta?.userAgent ?? '').slice(0, 200),
          },
          config.historyLimit,
        )
      },
    })
    try {
      listeningPort = await instance.listen()
      gate = instance
      logger.info?.(`[${PLUGIN_NAME}] 已监听 0.0.0.0:${listeningPort} → 127.0.0.1:${targetPort}`)
    } catch (error) {
      logger.error?.(`[${PLUGIN_NAME}] 监听失败：${(error && error.message) || error}`)
    }
  }

  /** 停监听。配置变了就停掉重起（端口可能变了）。 */
  async function stopGateway() {
    const instance = gate
    gate = undefined
    listeningPort = undefined
    if (instance === undefined) return
    try {
      await instance.close()
    } catch (error) {
      logger.warn?.(`[${PLUGIN_NAME}] 关监听时出错：${(error && error.message) || error}`)
    }
  }

  async function restartGateway() {
    await stopGateway()
    await startGateway()
  }

  // ── RPC 端点（客户端半区调这些）──────────────────────────────
  /**
   * 挂 RPC 通道。
   *
   * ⚠️ 必须**注册在注入进来的 web 上下文上**，否则 rpc.handle() 挂不到 webServer 上。
   *    DSH 0.1.5 的 rpc getter 会保留 Connection 服务自己的 context，所以要显式重绑一次。
   *    （这条照抄 dsh-workspace-mover 的实测结论，不是我推的。）
   */
  function mountRpc(owner) {
    const connection = owner?.connection
    if (!connection?.rpc?.handle) return undefined
    const rawConnection = connection[Symbol.for('cordis.original')] ?? connection
    const scopedConnection = rawConnection?.[Symbol.for('cordis.extend')]?.({ ctx: owner }) ?? connection

    return scopedConnection.rpc.handle(CHANNEL, async (endpoint, payload = {}) => {
      try {
        switch (endpoint) {
          case 'remote.status':
            return ok({
              running: gate !== undefined,
              port: listeningPort ?? null,
              configuredPort: config.port,
              hasPassword: typeof config.password === 'string' && config.password !== '',
              configPath: configPath(),
              dataDir: dataDir(),
              historyCount: readHistory().length,
              channel: CHANNEL,
            })

          case 'remote.config.get':
            // 明文密码就存在配置文件里，这里如实回给客户端半区
            return ok({ password: config.password, port: config.port })

          case 'remote.config.set': {
            const nextPort = Number(payload?.port)
            const nextPassword = typeof payload?.password === 'string' ? payload.password : config.password
            if (!Number.isInteger(nextPort) || nextPort <= 0 || nextPort > 65535) {
              return fail('bad-port', '端口必须是 1~65535 的整数')
            }
            const changed = nextPort !== config.port || nextPassword !== config.password
            writeConfig({ ...config, password: nextPassword, port: nextPort })
            config = readConfig()
            if (changed) await restartGateway()
            return ok({ port: config.port, hasPassword: config.password !== '', restarted: changed })
          }

          case 'remote.history.list':
            return ok(readHistory())

          case 'remote.history.clear':
            writeJson(historyPath(), [])
            return ok({ cleared: true })

          default:
            return fail('unknown-endpoint', `未知端点：${String(endpoint)}`)
        }
      } catch (error) {
        return fail('internal', String((error && error.message) || error))
      }
    })
  }

  // ── 接线 ────────────────────────────────────────────────────
  try {
    const disposeRpc = mountRpc(webCtx)
    void startGateway()
    // 插件卸载时收尾（cordis effect 的 disposer 形式）
    if (typeof ctx.effect === 'function') {
      ctx.effect(() => async () => {
        try {
          if (typeof disposeRpc === 'function') disposeRpc()
        } catch {
          /* 忽略 */
        }
        await stopGateway()
      }, `${PLUGIN_NAME}.lifecycle`)
    }
  } catch (error) {
    // apply 里绝不能抛出去 —— 抛出去插件整个不注册，症状会很难查
    logger.error?.(`[${PLUGIN_NAME}] 启动失败：${(error && error.message) || error}`)
  }
}

export const name = PLUGIN_NAME
export const channel = CHANNEL
export const inject = ['webServer']

export function apply(ctx) {
  // connection 可能比 webServer 晚就绪；两个都注进来，等它们可用再说。
  // 与 dsh-print-web-url 同一套等待姿势：等整棵树 settle，再确认两个服务都在。
  ctx.inject(['connection', 'webServer'], (webCtx) => {
    const loader = service(webCtx, 'loader')
    const settled = typeof loader?.await === 'function' ? loader.await() : undefined

    if (settled === undefined) {
      boot(ctx, webCtx)
      return
    }
    settled.then(
      () => {
        if (service(webCtx, 'webServer') !== undefined && service(webCtx, 'connection') !== undefined) {
          boot(ctx, webCtx)
        }
      },
      () => {
        /* 树没起来就不启动，交给别处报错 */
      },
    )
  })
}

export default { name, channel, inject, apply }
