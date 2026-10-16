// ============================================================
// dsh_webview_remote_client —— DSH WebView 远程客户端（显示名见 kAppTitle）
//
// 三个阶段：
//   choosing  有保存的凭据 → 选「用保存的连」还是「重新输入」
//   form      手输地址 + 密码
//   web       连上后在 WebView 里用 DSH 的 Web UI，顶部一条自己的栏：
//               左上「调试」→ 内核版本、垫片补了哪些 API、连接地址、当前 URL
//               右上「退出」→ 断开回登录页（已保存的凭据保留）
//
// ── 认证流程（与 开发思路.md §3「两层锁」一致）──────────────
//   1) 用【请求头】X-Gateway-Password 打 GET /__gateway/session
//      —— 密码【绝不】放进 URL（URL 会进历史/日志，HTTPS 也救不了）
//   2) 网关验过 → 204 + Set-Cookie: dsh-gw=…
//   3) 把这张 cookie 注入 WebView 的 CookieManager
//   4) 导航到 http://<地址>/ —— 之后 DSH 的会话 cookie 由 DSH 自己签发
//
// ── 凭据存储 ─────────────────────────────────────────────────
// 地址和密码存在系统安全存储里（Android Keystore / 鸿蒙安全存储），**不是明文**。
// 依赖里同时装了 flutter_secure_storage 主包与 _ohos 包 —— 该插件是**老式联邦
// 插件**，Dart 侧不用注册，原生插件用同一个 method channel。
// 写库时机 = **会话交换成功之后**，免得把打错的密码存下来。
//
// ── 未验证（别当已知条件）────────────────────────────────────
//   · 本文件改动尚未经过 flutter analyze / 构建验证
//   · OHOS 侧全链路未测（签名还没配）
//   · 「切输入法卡」的修法（manifest 改 adjustNothing + 网关注入键盘位移补丁）
//     是个**实验**，未验证；若发现固定定位的面板错位，见网关注释里的退路
// ============================================================

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
// ⚠️ 必须 import **ohos 那份**，不能用主包（flutter_secure_storage）。
//
// 原因：主包的 Dart 代码在 _selectOptions() 里没有鸿蒙分支，会直接抛
//   UnsupportedError('unsupported_platform')
// 实测症状：App 里报「写入失败：Unsupported operation：unsupported_platform」，
// 而且**调用根本到不了原生侧** —— 设备日志里 HUKS 全程无事发生，
// 所以一度误判成"鸿蒙密钥库不行"。
//
// ohos 包自带一份同样的 Dart API（类名也一致），但它的判断里多了一支：
//   } else if (Platform.operatingSystem == 'ohos') { return ohOptions... }
// 原生侧两个包共用同一个 method channel，所以只换 Dart 这边就够。
import 'package:flutter_secure_storage_ohos/flutter_secure_storage_ohos.dart';
import 'package:webview_flutter/webview_flutter.dart';

/// 网关自己的 cookie 名，与 dsh-remote-gateway 的 lib/gateway.js 保持一致。
const String kGatewayCookieName = 'dsh-gw';

/// App 显示名。桌面图标名、页面标题、App 内标题**统一用这一个**。
///
/// 显示名统一成 "DSH WebView 远程客户端"。
/// 改名字时平台侧那几处没法共用这个常量，要一起改：
///   · app/android/app/src/main/AndroidManifest.xml 的 android:label
///   · app/ohos/AppScope/resources/base/element/string.json 的 app_name
///   · app/ohos/entry/src/main/resources/{base,zh_CN,en_US}/element/string.json
///     的 EntryAbility_label
/// ⚠️ 包名（Android applicationId / 鸿蒙 bundleName）**不要动** ——
///    换包名等于换一个 App，手机上会当成两个，还得重新签名。
const String kAppTitle = 'DSH WebView 远程客户端';

/// 换 cookie 的端点，同样与内核保持一致。
const String kSessionPath = '/__gateway/session';

/// 告诉网关"这个客户端是什么平台" —— 网关拿它填连接历史的「平台」列。
///
/// 为什么必须自己声明：Dart 的 HttpClient 默认 UA 是 `Dart/<版本> (dart:io)`，
/// **既不说明安卓也不说明鸿蒙**，网关无从推断。所以只能客户端主动报一个。
///
/// ⚠️ 鸿蒙那条**必须排在最前**：`Platform.is*` 里没有它，而且不能想当然
///    它会不会命中别的分支（比如被当成 linux）。
String kClientPlatformTag() {
  final String os = Platform.operatingSystem;
  if (os == 'ohos' || os == 'harmonyos') return 'ohos';
  if (Platform.isAndroid) return 'android';
  if (Platform.isIOS) return 'ios';
  if (Platform.isMacOS) return 'macos';
  if (Platform.isWindows) return 'windows';
  if (Platform.isLinux) return 'linux';
  return os;
}

// ────────────────────────────────────────────────────────────
// 界面文案（中 → 英）
//
// 语言改成起始页上的手动按钮，不跟随系统。
//
// 做法：**中文原文直接当键**（gettext 那种）。为什么这样：
//   · 不用为二十多条文案再起二十多个键名；
//   · 漏翻的地方会**原样显示中文**，而不是显示成一个键名 —— 这点最关键：
//     漏翻是"看起来没翻"，不是"看起来坏了"。
//
// ⚠️ 已知取舍：同一句中文若在不同位置要翻成不同英文，这套就撑不住。
//    目前没有这种情况；真出现了，给那一条单独起一个键即可。
//
// 调试面板里的文案**故意不翻** —— 照 dsh-scrcpy 定下的规矩：
// 日志与诊断信息给开发看，不翻。
// ────────────────────────────────────────────────────────────

/// 中文（键）→ 英文。中文那一侧不用写 —— 键本身就是中文。
const Map<String, String> kEnDict = <String, String>{
  // App 内显示的标题。桌面图标名跟系统语言走，不走这里。
  'DSH WebView 远程客户端': 'DSH WebView Remote Client',

  // 起始页
  '有上次保存的连接信息': 'A saved connection was found',
  '地址': 'Address',
  '密码': 'Password',
  '••••••••（已保存）': '•••••••• (saved)',
  '重新输入': 'Enter again',
  '连接到本机的 DSH 网关': 'Connect to the DSH gateway on your computer',
  '网关地址': 'Gateway address',
  '记住地址和密码': 'Remember address and password',
  '存在系统安全存储里（Android Keystore / 鸿蒙安全存储），不是明文':
      'Kept in the system secure storage (Android Keystore / HarmonyOS secure storage), not in plain text',
  '密码只走请求头，不进 URL。':
      'The password travels only in a request header, never in the URL.',
  '连接': 'Connect',

  // 顶部栏
  '调试': 'Debug',
  '退出': 'Exit',
  '开源许可': 'Open-source licenses',

  // 出错提示。花括号是占位符，见 fillPlaceholders()。
  '请填网关地址，例如 192.168.1.110:8080':
      'Enter the gateway address, for example 192.168.1.110:8080',
  '请填密码': 'Enter the password',
  '地址看不懂：{base}': 'Cannot parse the address: {base}',
  '密码不对（网关回了 401）': 'Wrong password (the gateway answered 401)',
  '网关回了意外状态码：{code}': 'The gateway answered an unexpected status: {code}',
  '网关没发 {cookie} cookie，这不正常':
      'The gateway did not send the {cookie} cookie — that is not normal',
  '会话没建立成功：页面里没有 DSH 的 #root。请重新连接。':
      'The session did not come up: the page has no DSH #root. Please connect again.',
  '连不上 {base}（超过 {seconds} 秒没响应）\n常见原因：网关没在跑、被防火墙拦了、或者地址写错了。':
      'Cannot reach {base} (no response within {seconds}s).\n'
      'Common causes: the gateway is not running, a firewall is blocking it, '
      'or the address is wrong.',
  '连不上 {base}\n{message}': 'Cannot reach {base}\n{message}',
  'TLS 握手失败（地址是不是写了 https？）\n{error}':
      'TLS handshake failed (did you write https in the address?)\n{error}',
  '出错：{error}': 'Error: {error}',
};

/// 把 `{name}` 换成参数值。**没传的占位符原样留着** —— 一眼能看出漏传了，
/// 比悄悄替换成空字符串好排查。
String fillPlaceholders(String template, Map<String, String>? params) {
  if (params == null || params.isEmpty) return template;
  String out = template;
  params.forEach((String key, String value) {
    out = out.replaceAll('{$key}', value);
  });
  return out;
}

/// 凭据存储。Android 走 Keystore 支撑的加密存储；OHOS 走平台安全存储
/// （依赖里同时装了 flutter_secure_storage 主包与 flutter_secure_storage_ohos）。
const FlutterSecureStorage kCredentialStore = FlutterSecureStorage();

const String kStoreAddress = 'gateway_address';
const String kStorePassword = 'gateway_password';
const String kStoreRemember = 'remember_credentials';

/// 界面语言（`'zh'` / `'en'`）。
///
/// 语言由起始页上的按钮手动切，**连上之后不给切** ——
/// 所以它不是"跟随系统"，也不该去读系统语言。
///
/// 【AI 提的方案】塞进凭据存储：它**不是秘密**，但为了一个字符串再引一个
/// shared_preferences 依赖不值得 —— 这个存储本来就在，顺手放。
const String kStoreLanguage = 'ui_language';

/// 连接与请求超时。
///
/// 为什么必须有（实测）：服务端没起来时，如果防火墙把包**静默丢掉**而不是回 RST，
/// TCP 层要等自己那套重传/超时才失败 —— 体感 20 秒以上，看到的就是
/// "卡很久才报错"。见 `_connect` 里的说明。
const Duration _kConnectTimeout = Duration(seconds: 8);

void main() => runApp(const DshRemoteApp());

/// 当前处于哪个阶段。
enum _Stage { choosing, form, web }

class DshRemoteApp extends StatelessWidget {
  const DshRemoteApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: kAppTitle,
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF4C7DFF),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const ConnectPage(),
    );
  }
}

/// 两次变化间隔小于这个值，就认为它们属于**同一段动画里的连串变化**（键盘弹出那种）。
const Duration _kBurstGap = Duration(milliseconds: 90);

/// 连串变化期间，两次**提交**之间至少隔这么久。
///
/// 取 120ms 的理由：键盘动画大约 250ms，这样开头就立刻提交一次、中间再跟上两次，
/// 尺寸大致跟着动画走 —— 而不是等动画放完才跳。
const Duration _kThrottle = Duration(milliseconds: 120);

/// 给 WebView 套一层「会挑时机提交的尺寸」—— 目标是**少重排，但不人为拖延**。
///
/// ── 为什么需要 ────────────────────────────────────────────────
/// 如果让 Flutter 把每帧尺寸都转给 WebView，那个 React 页面会**连续重排十几次**，
/// 全砸在 UI 线程上 → 明显卡顿。（Flutter 的平台视图还有额外的重布局/表面处理
/// 开销，这是它比"WebView 直接当窗口"的浏览器更吃力的地方。）
///
/// ── 两条规则 ──────────────────────────────────────────────────
/// 1) **孤立跳变 → 立刻提交。** 旋转属于这种：系统一次性把新尺寸给过来，中间没有
///    连串变化。（**这一条是推断，我还没实测验证。**）
///    早先不分情况一律防抖，于是旋转被白白拖了一个 settle 时长 ——
///    实测现象：「动画播完了还要卡一段时间才会动」。
/// 2) **连串变化 → 按节流提交。** 键盘弹出那种逐帧变化：开头立刻提交一次
///    （所以尺寸在动画一开始就跟着变），中间的抖动合并掉，最后再补一次保证落地。
///
/// ── 代价 ──────────────────────────────────────────────────────
/// 两次提交之间 WebView 保持旧尺寸并被裁剪，看起来像定格，然后跳一下。
class _DebouncedSize extends StatefulWidget {
  const _DebouncedSize({required this.child, this.onSettled});

  final Widget child;

  /// 提交时回调（incoming 与 committed 此刻相同；留两个参数是为了以后可分辨）。
  final void Function(Size incoming, Size committed)? onSettled;

  @override
  State<_DebouncedSize> createState() => _DebouncedSizeState();
}

class _DebouncedSizeState extends State<_DebouncedSize> {
  Size? _committed;

  /// 攒着、还没到提交时机的尺寸（节流窗口内到达的那些）
  Size? _pending;
  Timer? _timer;
  DateTime? _lastChange;
  DateTime? _lastCommit;

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  /// 采用一个新尺寸。
  ///
  /// `rebuild` 决定要不要 setState：
  ///   · **从 build 里调时必须传 false** —— `_schedule` 是在 `LayoutBuilder` 的
  ///     builder 里被调用的，那一瞬间调 setState 会抛
  ///     「setState() called during build」。直接赋值就够了：这次 build 马上
  ///     就会读到新的 `_committed`。
  ///   · 从 Timer 里调时传 true —— 那时不在 build 中，需要主动触发重绘。
  void _adopt(Size size, {required bool rebuild}) {
    _timer?.cancel();
    _pending = null;
    _lastCommit = DateTime.now();
    if (rebuild) {
      setState(() => _committed = size);
    } else {
      _committed = size;
    }
    widget.onSettled?.call(size, size);
  }

  void _schedule(Size incoming) {
    if (_committed == null) {
      // 第一帧：直接采用。一上来就"定格"反而奇怪。
      _adopt(incoming, rebuild: false);
      return;
    }
    if (incoming == _committed) return;

    final now = DateTime.now();
    final previousChange = _lastChange;
    _lastChange = now;

    // 规则一：距上次变化已超过 _kBurstGap → 这是一次**孤立跳变**（旋转就是这种）。
    // 立刻提交，不引入任何人为延迟。
    final lone =
        previousChange == null || now.difference(previousChange) > _kBurstGap;

    // 规则二：连串变化里按节流提交 —— 距上次提交够久就立刻提交一次（leading edge），
    // 于是尺寸在动画开头就跟着变；不够久就先攒着，等窗口到期再提交。
    final sinceCommit = _lastCommit == null ? null : now.difference(_lastCommit!);
    final due = sinceCommit == null || sinceCommit >= _kThrottle;

    if (lone || due) {
      _adopt(incoming, rebuild: false);
      return;
    }

    // 走到这里 sinceCommit 一定非空（due 为 false 蕴含它非空）—— 分析器确认
    // 这个提升成立（它把上一版那句显式判空报成"条件恒为 false"），所以直接算即可。
    //
    // 注：§13.5 记的那个坑是"局部变量不能在自己的初始化表达式里被闭包引用"，
    // 和这里不是一回事 —— 那处的结论只适用于那一处，别过度推广。
    final remaining = _kThrottle - sinceCommit;

    _pending = incoming;
    _timer?.cancel();
    _timer = Timer(remaining, () {
      if (!mounted) return;
      final next = _pending;
      if (next == null) return;
      _adopt(next, rebuild: true);
    });
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (BuildContext context, BoxConstraints constraints) {
        final incoming = Size(constraints.maxWidth, constraints.maxHeight);
        _schedule(incoming);

        final committed = _committed ?? incoming;
        return ClipRect(
          child: OverflowBox(
            alignment: Alignment.topLeft,
            minWidth: 0,
            maxWidth: double.infinity,
            minHeight: 0,
            maxHeight: double.infinity,
            child: SizedBox(
              width: committed.width,
              height: committed.height,
              child: widget.child,
            ),
          ),
        );
      },
    );
  }
}

class ConnectPage extends StatefulWidget {
  const ConnectPage({super.key});

  @override
  State<ConnectPage> createState() => _ConnectPageState();
}

class _ConnectPageState extends State<ConnectPage> {
  final TextEditingController _address = TextEditingController();
  final TextEditingController _password = TextEditingController();

  _Stage _stage = _Stage.form;
  bool _busy = false;

  /// 界面语言：`'zh'` 或 `'en'`。启动时从存储读回，每切一次存一次。
  String _lang = 'zh';
  bool _remember = true;
  String? _error;
  WebViewController? _webView;

  /// 最近一次"已提交"给 WebView 的尺寸（调试面板用，看防抖有没有按预期工作）
  Size? _committedViewSize;

  /// 启动时读到的已存凭据（choosing 页用它显示摘要，也用来直接连接）
  String _savedAddress = '';
  String _savedPassword = '';

  /// 存储最近一次读/写的结果 —— **必须显示在调试面板里**。
  ///
  /// 为什么不只写日志：鸿蒙上 Dart 的 debugPrint **进不了 hilog**（实测），
  /// 只写日志等于没写。上一轮排查"凭据一直存不上"时，就是因为错误被吞进
  /// 一个在设备上看不见的地方，白花了一个小时。
  String _storageStatus = '(尚未读写存储)';

  void _setStorageStatus(String message) {
    debugPrint('[credentials] $message');
    if (!mounted) {
      _storageStatus = message;
      return;
    }
    setState(() => _storageStatus = message);
  }

  @override
  void initState() {
    super.initState();
    _restoreCredentials();
  }

  @override
  void dispose() {
    _address.dispose();
    _password.dispose();
    super.dispose();
  }

  // ────────────────────────────────────────────────────────────
  // 凭据存储
  // ────────────────────────────────────────────────────────────

  /// 启动时读回凭据。**读失败不报错** —— 存储不可用时退回手工输入，
  /// 不该因为存储的问题打不开 App。
  Future<void> _restoreCredentials() async {
    try {
      final remember = await kCredentialStore.read(key: kStoreRemember);
      final address = await kCredentialStore.read(key: kStoreAddress) ?? '';
      final password = await kCredentialStore.read(key: kStorePassword) ?? '';
      final lang = await kCredentialStore.read(key: kStoreLanguage);
      if (!mounted) return;

      final usable = remember != '0' && address.isNotEmpty && password.isNotEmpty;
      _setStorageStatus(
        usable
            ? '读取成功 ✓ 有已保存凭据'
            : '读取成功，但内容为空 —— remember=$remember，'
                '地址${address.isEmpty ? '空' : '有'}，密码${password.isEmpty ? '空' : '有'}',
      );
      setState(() {
        // 只认 en，其余（空、旧值、被改坏）一律当中文 ——
        // 绝不给它机会让界面显示成键名。
        _lang = (lang == 'en') ? 'en' : 'zh';
        _remember = remember != '0';
        _savedAddress = address;
        _savedPassword = password;
        // 表单也预填地址 —— 地址不是秘密，省得重打
        _address.text = address;
        _stage = usable ? _Stage.choosing : _Stage.form;
      });
    } catch (error) {
      _setStorageStatus('读取失败 ✗ $error');
      if (mounted) setState(() => _stage = _Stage.form);
    }
  }

  /// **连上之后才写** —— 免得把打错的密码存下来。
  Future<void> _persistCredentials(String address, String password) async {
    try {
      await kCredentialStore.write(key: kStoreRemember, value: _remember ? '1' : '0');
      if (_remember) {
        await kCredentialStore.write(key: kStoreAddress, value: address);
        await kCredentialStore.write(key: kStorePassword, value: password);
      } else {
        await kCredentialStore.delete(key: kStoreAddress);
        await kCredentialStore.delete(key: kStorePassword);
      }

      // ★ 内存里那两份也要跟着更新。
      //
      // 为什么必须有这一步（这是个真实 bug，已实测）：
      //   `_savedAddress/_savedPassword` 原本**只在启动时**由 _restoreCredentials()
      //   赋值。首次使用的情况下启动时存储是空的 → 这两个变量一直是 ''。
      //   手动输入并连上后，存储写进去了，但内存没同步；
      //   这时点【退出】——_disconnect() 用这两个变量判断"有没有存过凭据"，
      //   算出 false → 落到**空密码的表单页**，
      //   看起来就像"退出把登录凭据删了"，其实存储里那份好好的。
      _savedAddress = _remember ? address : '';
      _savedPassword = _remember ? password : '';
      _setStorageStatus(_remember ? '写入成功 ✓' : '已按要求清除存储 ✓');
    } catch (error) {
      _setStorageStatus('写入失败 ✗ $error');
    }
  }

  // ────────────────────────────────────────────────────────────
  // 三个阶段之间的切换
  // ────────────────────────────────────────────────────────────

  /// choosing 页：用保存的凭据连（把它填进输入框后走同一条连接路径）
  Future<void> _useSaved() async {
    _address.text = _savedAddress;
    _password.text = _savedPassword;
    await _connect();
  }

  /// choosing 页：改为手工输入。只保留地址，密码要重新输入。
  void _reenter() {
    setState(() {
      _stage = _Stage.form;
      _password.clear();
      _error = null;
    });
  }

  /// 顶部栏「退出」：断开回登录页。已保存的凭据**保留**，
  /// 所以下次进来还能走 choosing 页。
  void _disconnect() {
    _password.clear(); // 不把密码留在内存里
    setState(() {
      _webView = null;
      _error = null;
      final hasSaved = _remember && _savedAddress.isNotEmpty && _savedPassword.isNotEmpty;
      _stage = hasSaved ? _Stage.choosing : _Stage.form;
    });
  }

  /// 出问题时退回**原生**表单并给出原因。
  /// 关键：绝不把网关返回的网页当成登录页来用 —— 网关那个端口本来就不提供网页。
  void _failToForm(String message) {
    _password.clear();
    setState(() {
      _webView = null;
      _error = message;
      _stage = _Stage.form;
    });
  }

  // ────────────────────────────────────────────────────────────
  // 连接
  // ────────────────────────────────────────────────────────────

  /// 把输入收敛成一个可用的 base URL。接受 "192.168.1.110:8080" 这种省 scheme 的写法。
  String _normalizeBase(String raw) {
    var text = raw.trim();
    if (text.isEmpty) return '';
    if (!text.contains('://')) text = 'http://$text';
    while (text.endsWith('/')) {
      text = text.substring(0, text.length - 1);
    }
    return text;
  }

  /// 从 Set-Cookie 头里挑出指定名字的值。只看第一段 `name=value`。
  String? _pickCookie(List<String> setCookies, String name) {
    for (final raw in setCookies) {
      final first = raw.split(';').first.trim();
      final eq = first.indexOf('=');
      if (eq <= 0) continue;
      if (first.substring(0, eq) == name) return first.substring(eq + 1);
    }
    return null;
  }

  Future<void> _connect() async {
    FocusScope.of(context).unfocus();

    final base = _normalizeBase(_address.text);
    final password = _password.text;

    if (base.isEmpty) {
      setState(() {
        _stage = _Stage.form;
        _error = tr('请填网关地址，例如 192.168.1.110:8080');
      });
      return;
    }
    if (password.isEmpty) {
      setState(() {
        _stage = _Stage.form;
        _error = tr('请填密码');
      });
      return;
    }

    final parsed = Uri.tryParse(base);
    if (parsed == null || parsed.host.isEmpty) {
      setState(() {
        _stage = _Stage.form;
        _error = tr('地址看不懂：{base}', <String, String>{'base': base});
      });
      return;
    }

    setState(() {
      _busy = true;
      _error = null;
    });

    // connectionTimeout 是"连不上就早点放弃"；请求本身再加 per-await 超时。
    //
    // 为什么必须加（实测）：服务端没起来时，如果防火墙把包**静默丢掉**而不是回
    // RST，TCP 层要等自己那套重传/超时（实测体感 20 秒以上）才失败 ——
    // 看到的就是"卡很久才报错"。
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
    try {
      // ── 1) 用请求头换网关 cookie ─────────────────────────────
      final request = await client.getUrl(parsed.resolve(kSessionPath));
      request.headers.set('X-Gateway-Password', password);
      // 顺手报一下平台：网关用它填连接历史的「平台」列（不报就永远是 —）
      request.headers.set('X-Client-Platform', kClientPlatformTag());

      final response = await request.close().timeout(_kConnectTimeout);
      await response.drain<void>().timeout(_kConnectTimeout);

      if (response.statusCode == 401) {
        setState(() {
          _stage = _Stage.form;
          _error = tr('密码不对（网关回了 401）');
        });
        return;
      }
      if (response.statusCode != 204) {
        setState(() {
          _stage = _Stage.form;
          _error = tr('网关回了意外状态码：{code}',
              <String, String>{'code': '${response.statusCode}'});
        });
        return;
      }

      final cookieValue = _pickCookie(
        response.headers['set-cookie'] ?? const <String>[],
        kGatewayCookieName,
      );
      if (cookieValue == null) {
        setState(() {
          _stage = _Stage.form;
          _error = tr('网关没发 {cookie} cookie，这不正常',
              <String, String>{'cookie': kGatewayCookieName});
        });
        return;
      }

      // 连上了才记 —— 打错的密码不该被存下来
      await _persistCredentials(base, password);

      // ── 2) 注入 WebView 的 CookieManager ─────────────────────
      await WebViewCookieManager().setCookie(
        WebViewCookie(
          name: kGatewayCookieName,
          value: cookieValue,
          domain: parsed.host,
          path: '/',
        ),
      );

      // ── 3) 建 WebView 并导航 ────────────────────────────────
      // ⚠️ 这里**必须用 `late final`**，不能写 `final controller = WebViewController()..…`
      //
      // 原因：下面的 onPageFinished 要引用 controller 自己（去页面里查 #root），
      // 而 Dart 不让在局部变量的初始化表达式里引用该变量 —— 哪怕引用发生在闭包内部、
      // 运行时其实完全没问题。两种"看起来能绕开"的写法实测都被否掉了：
      //   1) `final controller = WebViewController()..… controller …`
      //      → Local variable 'controller' can't be referenced before it is declared
      //   2) 拆成 `final controller; controller = … controller …;`
      //      → The final variable 'controller' can't be read because it's
      //        potentially unassigned at this point
      // `late` 是唯一能让流分析放行的写法：它表示"读的时候它一定已经赋值"。
      late final WebViewController controller;
      controller = WebViewController()
        ..setJavaScriptMode(JavaScriptMode.unrestricted)
        ..setBackgroundColor(const Color(0xFF0F1115))
        // 诊断用：把 WebView 内部的 console 与加载错误转发到 Flutter 日志。
        // 抓法：adb logcat 里过滤 `[webview` 前缀。
        // 这两个 API 在 Android 和 OHOS 两份实现里都有，所以不用分平台写。
        ..setOnConsoleMessage((JavaScriptConsoleMessage message) {
          debugPrint('[webview:${message.level}] ${message.message}');
        })
        ..setNavigationDelegate(
          NavigationDelegate(
            onWebResourceError: (WebResourceError error) {
              debugPrint(
                '[webview:error] code=${error.errorCode} '
                'desc=${error.description} type=${error.errorType} url=${error.url}',
              );
            },
            onUrlChange: (UrlChange change) {
              debugPrint('[webview:url] ${change.url}');
            },
            onPageFinished: (url) async {
              // ⚠️ 只在"**确实是根路径、且不带 token**"时才判。
              //
              // 为什么：首次连接时 WebView 没有 dsh-auth cookie，网关注入 token，
              // DSH 收到后 303 跳回 / —— WebView 可能为那个**跳转中间文档**也触发
              // 一次 onPageFinished，而它当然没有 #root，会造成一次"假失败"。
              //
              // 声明：**这不是**"DSH 页面自己报连接失败"那个问题的原因（那另有其事），
              // 但这里是实打实的隐患，顺手修掉。
              final parsed = Uri.tryParse(url);
              if (parsed == null ||
                  parsed.path != '/' ||
                  parsed.queryParameters.containsKey('token')) {
                debugPrint('[webview:page-finished] 跳过（非根路径或带 token）：$url');
                return;
              }

              // 确认拿到的确实是 DSH 应用本身：它的 index.html 里有
              // <div id="root">，App 挂在上面。没有它说明会话没建立成功。
              final hasRoot = await _evalJs(
                "document.getElementById('root') !== null",
                controller,
              );
              debugPrint('[webview:page-finished] $url root=$hasRoot');
              if (hasRoot != 'true' && mounted) {
                _failToForm(tr('会话没建立成功：页面里没有 DSH 的 #root。请重新连接。'));
              }
            },
          ),
        );

      await controller.loadRequest(Uri.parse('$base/'));

      if (!mounted) return;
      setState(() {
        _webView = controller;
        _stage = _Stage.web;
      });
    } on TimeoutException catch (_) {
      // 超时和"连不上"要分开报：超时通常是防火墙静默丢包 / 服务端假死，
      // 而 SocketException 通常是地址错或服务没起。
      setState(() {
        _stage = _Stage.form;
        _error = tr(
          '连不上 {base}（超过 {seconds} 秒没响应）\n'
          '常见原因：网关没在跑、被防火墙拦了、或者地址写错了。',
          <String, String>{'base': base, 'seconds': '${_kConnectTimeout.inSeconds}'},
        );
      });
    } on SocketException catch (error) {
      // 连不上通常就三种：地址写错 / 网关没在跑 / 防火墙拦了。
      setState(() {
        _stage = _Stage.form;
        _error = tr('连不上 {base}\n{message}',
            <String, String>{'base': base, 'message': error.message});
      });
    } on HandshakeException catch (error) {
      setState(() {
        _stage = _Stage.form;
        _error = tr('TLS 握手失败（地址是不是写了 https？）\n{error}',
            <String, String>{'error': '$error'});
      });
    } catch (error) {
      setState(() {
        _stage = _Stage.form;
        _error = tr('出错：{error}', <String, String>{'error': '$error'});
      });
    } finally {
      client.close(force: true);
      if (mounted) setState(() => _busy = false);
    }
  }

  // ────────────────────────────────────────────────────────────
  // 调试面板
  // ────────────────────────────────────────────────────────────

  /// 在页面里求值并拿走字符串结果。
  /// `runJavaScriptReturningResult` 返回的是 **JSON 编码**的值，字符串会带引号，
  /// 所以这里用 jsonDecode 还原，而不是手撕引号。
  Future<String> _evalJs(String script, [WebViewController? override]) async {
    final controller = override ?? _webView;
    if (controller == null) return '(尚未连接)';
    try {
      final raw = await controller.runJavaScriptReturningResult(script);
      final text = raw.toString();
      if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
        return jsonDecode(text) as String;
      }
      return text;
    } catch (error) {
      return '(读取失败：$error)';
    }
  }

  /// 打开第三方开源许可页。
  ///
  /// 为什么直接调 showLicensePage 就够、不用自己列一张表：
  /// Flutter 打包时会把**依赖图里每个包的 LICENSE** 汇总成 NOTICES 随产物发出
  /// （实测：APK 与 HAP 的 flutter_assets 下都有 NOTICES.Z），运行时由
  /// LicenseRegistry 读出来。所以这里只是**给一个入口** ——
  /// 文本早就在包里了，之前只是没人能点到。
  ///
  /// 【未验证】页面自身的框架文字（"Licenses"、"VIEW LICENSES" 之类）目前是英文：
  /// 那来自 MaterialLocalizations，只有引入 flutter_localizations 才会跟着我们的
  /// 中英切换走。许可正文本来就是英文，所以先这样，没为它引依赖。
  /// ⚠️ 返回类型是 `void`，**不是** `Future<void>` —— showLicensePage 本身
  /// 就返回 void（实测：写成 `Future<void>` 会被 analyzer 直接拦下）。
  void _showLicenses() {
    showLicensePage(
      context: context,
      applicationName: tr(kAppTitle),
      applicationIcon: const Icon(Icons.info_outline),
    );
  }

  Future<void> _showDebugInfo() async {
    final currentUrl = await _evalJs('String(location.href)');
    final kernel = await _evalJs('navigator.userAgent');
    final shim = await _evalJs(
      'JSON.stringify(globalThis.__DSH_GATEWAY_SHIM__ ?? null, null, 1)',
    );

    if (!mounted) return;
    await showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      builder: (sheetContext) => SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(20, 0, 20, 28),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(
                '调试信息',
                style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 14),
              _debugRow('连接地址', _address.text.trim()),
              _debugRow('当前页面', currentUrl),
              _debugRow('内核 / UA', kernel),
              _debugRow(
                'WebView 已提交尺寸',
                _committedViewSize == null
                    ? '(未知)'
                    : '${_committedViewSize!.width.round()} × '
                        '${_committedViewSize!.height.round()}',
              ),
              _debugRow('网关注入的垫片', shim),
              _debugRow('存储（记住密码）', _storageStatus),
              const Divider(height: 28),
              const Text(
                '「网关注入的垫片」来自页面里的 __DSH_GATEWAY_SHIM__，由网关注入的客户端脚本写入 —— '
                '里面的 kernel 是内核版本，installed 是它替你补上的缺失 API，'
                'enterShim / keyboardShim 表示回车改写与键盘补丁是否装上了。',
                style: TextStyle(fontSize: 11, color: Colors.white38),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _debugRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(label, style: const TextStyle(fontSize: 11, color: Colors.white54)),
          const SizedBox(height: 3),
          SelectableText(value, style: const TextStyle(fontSize: 12, height: 1.4)),
        ],
      ),
    );
  }

  // ────────────────────────────────────────────────────────────
  // 界面
  // ────────────────────────────────────────────────────────────

  /// 连接后的顶部栏：左上调试、右上退出。
  Widget _buildTopBar() {
    return Container(
      color: const Color(0xFF15171C),
      padding: const EdgeInsets.symmetric(horizontal: 6),
      child: Row(
        children: <Widget>[
          TextButton.icon(
            onPressed: _showDebugInfo,
            icon: const Icon(Icons.bug_report_outlined, size: 18),
            label: Text(tr('调试'), style: const TextStyle(fontSize: 13)),
          ),
          const Spacer(),
          TextButton.icon(
            onPressed: _showLicenses,
            icon: const Icon(Icons.article_outlined, size: 18),
            label: Text(tr('开源许可'), style: const TextStyle(fontSize: 13)),
          ),
          TextButton.icon(
            onPressed: _disconnect,
            icon: const Icon(Icons.logout, size: 18),
            label: Text(tr('退出'), style: const TextStyle(fontSize: 13)),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorBox() {
    final error = _error;
    if (error == null) return const SizedBox.shrink();
    return Container(
      margin: const EdgeInsets.only(top: 16),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0x33FF6B6B),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Text(
        error,
        style: const TextStyle(fontSize: 13, color: Color(0xFFFFB4B4)),
      ),
    );
  }

  /// 取文案。`key` 是**中文原文**（见 kEnDict 上方的说明）。
  ///
  /// 英文里没有这条 → 原样返回中文。**绝不返回 null 或 '[object]'。**
  String tr(String key, [Map<String, String>? params]) {
    final String text = _lang == 'en' ? (kEnDict[key] ?? key) : key;
    return fillPlaceholders(text, params);
  }

  /// 切换语言。按钮只在起始页出现 —— 连上之后不给切。
  void _toggleLang() {
    setState(() => _lang = _lang == 'en' ? 'zh' : 'en');
    _persistLanguage();
  }

  /// 语言**切换就立刻落盘**（不是连上才写 —— 可能切完就退出 App）。
  /// 写失败只记日志、不弹错：语言存不住是小事，不值得弹错。
  Future<void> _persistLanguage() async {
    try {
      await kCredentialStore.write(key: kStoreLanguage, value: _lang);
    } catch (error) {
      debugPrint('[language] 保存失败：$error');
    }
  }

  /// 起始页那个语言按钮。显示的是**点了会变成什么**（当前中文就显示 English）。
  Widget _buildLangToggle() {
    return Align(
      alignment: Alignment.centerRight,
      child: TextButton(
        onPressed: _busy ? null : _toggleLang,
        child: Text(
          _lang == 'en' ? '中文' : 'English',
          style: const TextStyle(fontSize: 12),
        ),
      ),
    );
  }

  /// 起始页最底部那一行：署名 + 开源许可入口。
  ///
  /// 为什么从**顶层函数**挪成 State 的方法：要调 `tr()`（中英切换）和
  /// `showLicensePage()`（要 context），两者都需要实例上下文。
  /// 两个起始页（choosing / form）在同一个 State 里，所以共用没问题。
  Widget _buildFooter() {
    return Padding(
      padding: const EdgeInsets.only(top: 6, bottom: 14),
      child: Wrap(
        alignment: WrapAlignment.center,
        crossAxisAlignment: WrapCrossAlignment.center,
        spacing: 4,
        children: <Widget>[
          const Text(
            'Made by NS-ZZJ',
            style: TextStyle(fontSize: 11, color: Colors.white38),
          ),
          TextButton(
            onPressed: _showLicenses,
            style: TextButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 6),
              minimumSize: Size.zero,
              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            ),
            child: Text(
              tr('开源许可'),
              style: const TextStyle(fontSize: 11, color: Colors.white38),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildBusyChild() {
    return _busy
        ? const SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(strokeWidth: 2),
          )
        : Text(tr('连接'), style: const TextStyle(fontSize: 16));
  }

  /// choosing 阶段：有保存的凭据，让选。
  Widget _buildChoosing() {
    return Scaffold(
      // 署名钉在页面最底部。用 Scaffold 自己的底栏位，不必重排 body 的嵌套结构。
      bottomNavigationBar: _buildFooter(),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 380),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  _buildLangToggle(),
                  Text(
                    tr(kAppTitle),
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    tr('有上次保存的连接信息'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 13, color: Colors.white60),
                  ),
                  const SizedBox(height: 26),
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: const Color(0xFF1B1E25),
                      borderRadius: BorderRadius.circular(12),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: <Widget>[
                        Text(tr('地址'), style: const TextStyle(fontSize: 11, color: Colors.white54)),
                        const SizedBox(height: 3),
                        Text(_savedAddress, style: const TextStyle(fontSize: 14)),
                        const SizedBox(height: 12),
                        Text(tr('密码'), style: const TextStyle(fontSize: 11, color: Colors.white54)),
                        const SizedBox(height: 3),
                        Text(tr('••••••••（已保存）'), style: const TextStyle(fontSize: 14)),
                      ],
                    ),
                  ),
                  _buildErrorBox(),
                  const SizedBox(height: 22),
                  FilledButton(
                    onPressed: _busy ? null : _useSaved,
                    style: FilledButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                    ),
                    child: _buildBusyChild(),
                  ),
                  const SizedBox(height: 10),
                  OutlinedButton(
                    onPressed: _busy ? null : _reenter,
                    style: OutlinedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 14),
                    ),
                    child: Text(tr('重新输入'), style: const TextStyle(fontSize: 15)),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// form 阶段：手输地址与密码。
  Widget _buildForm() {
    return Scaffold(
      // 同上：署名钉底。
      bottomNavigationBar: _buildFooter(),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 380),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: <Widget>[
                  _buildLangToggle(),
                  Text(
                    tr(kAppTitle),
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    tr('连接到本机的 DSH 网关'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 13, color: Colors.white60),
                  ),
                  const SizedBox(height: 28),
                  TextField(
                    controller: _address,
                    keyboardType: TextInputType.url,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: InputDecoration(
                      labelText: tr('网关地址'),
                      hintText: '192.168.1.110:8080',
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 14),
                  TextField(
                    controller: _password,
                    obscureText: true,
                    autocorrect: false,
                    enableSuggestions: false,
                    onSubmitted: (_) => _busy ? null : _connect(),
                    decoration: InputDecoration(
                      labelText: tr('密码'),
                      border: const OutlineInputBorder(),
                    ),
                  ),
                  _buildErrorBox(),
                  const SizedBox(height: 20),
                  FilledButton(
                    onPressed: _busy ? null : _connect,
                    style: FilledButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 16),
                    ),
                    child: _buildBusyChild(),
                  ),
                  const SizedBox(height: 6),
                  SwitchListTile(
                    value: _remember,
                    onChanged: (value) => setState(() => _remember = value),
                    contentPadding: EdgeInsets.zero,
                    title: Text(tr('记住地址和密码'), style: const TextStyle(fontSize: 14)),
                    subtitle: Text(
                      tr('存在系统安全存储里（Android Keystore / 鸿蒙安全存储），不是明文'),
                      style: const TextStyle(fontSize: 11),
                    ),
                  ),
                  Text(
                    tr('密码只走请求头，不进 URL。'),
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 11, color: Colors.white38),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  /// web 阶段：顶部栏 + WebView。
  Widget _buildWeb() {
    final controller = _webView;
    if (controller == null) return _buildForm();
    return Scaffold(
      body: SafeArea(
        child: Column(
          children: <Widget>[
            _buildTopBar(),
            Expanded(
              child: _DebouncedSize(
                onSettled: (incoming, committed) => _committedViewSize = committed,
                child: WebViewWidget(controller: controller),
              ),
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    switch (_stage) {
      case _Stage.choosing:
        return _buildChoosing();
      case _Stage.form:
        return _buildForm();
      case _Stage.web:
        return _buildWeb();
    }
  }
}
