// dsh-webview-remote-server — client half（source-as-product，无需构建）
//
// 在 DSH 设置页左栏加一栏「WebView 远程」：
//   密码配置 / 端口配置 / 连接历史（地址 + 平台 + 年月日时分秒）
//
// ── 非本机时怎么办（跟模型页一样的逻辑、一样的报错）──────
// 判断依据和 DSH 自己的设置页**同一个来源**：ctx.remote.$host.isLoopback
//   （DSH 那边是 persistence = isLoopback ? 'host' : 'memory'，远程时设置镜像
//    直接进入终态 'unavailable'）
// 非本机时只渲染那句话，与模型页**逐字一致**：
//   Settings are unavailable in this browser.
// 注意：那句是**硬编码英文**（不在任何字典里）—— 界面是中文却看到英文就是这个原因。
// 所以这里也照原样硬编码，不做本地化。
// 判断不出来时（拿不到 remote 服务）**按非本机处理**：宁可本机看不到，
// 也不要把密码给一个来路不明的调用方。
//
// ── 模块形状（照 dsh-workspace-mover，这是 DSH 客户端半区的壳）──────────
// 往 window.__ModuleLoader__ 注册一个工厂，工厂里做 CommonJS：
//   factory(require) → { var module = { exports: {} }; … module.exports = { inject, apply } }
// React 由 require("react") 提供，**不是** ES import。
//
// ── 语言 ─────────────────────────────────────────────────────
// 不用 locale.register/bind（热重载会报 "namespace already has locale"，实测坑），
// 每次现读活动语言、自己挑字典 —— 同 dsh-scrcpy-core 的做法。
window.__ModuleLoader__.load({
	// 这里必须写**带 scope 的完整包名**（不是 cordis.patch.yml 里那个短 id）——
	// 照 dsh-scrcpy-core 的写法：它注册的 id 是 '@nszzj/dsh-scrcpy-core'。
	id: "@nszzj/dsh-webview-remote-server",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		const React = require("react");

		/** RPC 通道，与宿主半区（lib/index.js）里的 CHANNEL 保持一致。 */
		const CHANNEL = "/webview-remote-server";

		/** 非本机时显示的那句话 —— 与 DSH 模型页逐字一致（硬编码英文，故意不翻译）。 */
		const UNAVAILABLE_TEXT = "Settings are unavailable in this browser.";

		// ────────────────────────────────────────────────────────
		// 字典（中英双语；只翻界面文案，不翻数据）
		// ────────────────────────────────────────────────────────
		const ZH = {
			nav: "WebView 远程",
			title: "WebView 远程接入",
			intro: "让手机通过局域网连到这台机器上的 DSH。修改后立即生效，不需要重启。",
			secPassword: "访问密码",
			passwordHint: "手机 App 用它进门。这是唯一的一道门 —— 拿到它就能在这台机器上执行命令。",
			passwordPlaceholder: "设一个密码",
			secPort: "监听端口",
			portHint: "网关在这个端口上等手机。改端口后要给手机填新的地址。",
			save: "保存",
			saving: "保存中…",
			saved: "已保存",
			saveFailed: "保存失败",
			statusRunning: "正在监听 0.0.0.0:{port}",
			statusStopped: "未启动（还没设密码）",
			secHistory: "连接历史",
			historyEmpty: "还没有连接记录。",
			colTime: "时间",
			colPlatform: "平台",
			colAddress: "地址",
			platformAndroid: "安卓",
			platformOhos: "鸿蒙",
			loadFailed: "读取配置失败",
		};

		const EN = {
			nav: "WebView Remote",
			title: "WebView remote access",
			intro: "Let a phone reach the DSH on this machine over the LAN. Changes apply immediately, no restart needed.",
			secPassword: "Access password",
			passwordHint: "The phone App uses it to get in. It is the only lock — whoever has it can run commands on this machine.",
			passwordPlaceholder: "Set a password",
			secPort: "Listen port",
			portHint: "The gateway waits for the phone on this port. Changing it means entering a new address on the phone.",
			save: "Save",
			saving: "Saving…",
			saved: "Saved",
			saveFailed: "Could not save",
			statusRunning: "Listening on 0.0.0.0:{port}",
			statusStopped: "Not started (no password yet)",
			secHistory: "Connection history",
			historyEmpty: "No connections recorded yet.",
			colTime: "Time",
			colPlatform: "Platform",
			colAddress: "Address",
			platformAndroid: "Android",
			platformOhos: "HarmonyOS",
			loadFailed: "Could not read the configuration",
		};

		// ────────────────────────────────────────────────────────
		// 小工具
		// ────────────────────────────────────────────────────────

		/** 代替 JSX：h("div", { style: … }, 子元素…) */
		function h(tag, props, ...children) {
			return React.createElement(tag, props ?? null, ...children);
		}

		/** 占位替换：{name} 用 params 里的值；缺参数就原样留着（便于发现漏传）。 */
		function tmpl(s, params) {
			if (!params) return s;
			return String(s).replace(/\{(\w+)\}/g, function (m, k) {
				return Object.prototype.hasOwnProperty.call(params, k) ? String(params[k]) : m;
			});
		}

		/** 时间戳 → 年月日时分秒（本地时区）。 */
		function formatTime(at) {
			try {
				const d = new Date(at);
				const p = (n) => String(n).padStart(2, "0");
				return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " "
					+ p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
			} catch (e) {
				return String(at);
			}
		}

		// ────────────────────────────────────────────────────────
		// 语言
		// ────────────────────────────────────────────────────────

		/** 出厂作用域里接上的 locale 服务（由 apply 里 bindLocale 赋值）。 */
		let localeSvc = null;

		function warnPlugin(msg) {
			try { console.warn("[webview-remote-server] " + String(msg)); } catch (e) { /* 忽略 */ }
		}

		/**
		 * 读 DSH 当前语言。
		 * ⚠️ 必须用 getSnapshot().active：getLocale() 返回的是语言**定义对象**
		 *    （有 id/label/fallback），没有 active 字段。
		 */
		function readActiveLocale() {
			try {
				const s = localeSvc && localeSvc.getSnapshot ? localeSvc.getSnapshot() : null;
				if (s && s.active) return String(s.active);
			} catch (e) { /* 下一个兜底 */ }
			try {
				const d = localeSvc && localeSvc.getLocale ? localeSvc.getLocale() : null;
				if (d && d.id) return String(d.id);
			} catch (e) { /* 放弃 */ }
			return null;
		}

		/** 取文案：自己挑字典（不用 register/bind —— 热重载会报 namespace 重复）。 */
		function T(key, params) {
			const dict = (readActiveLocale() === "en") ? EN : ZH;
			const s = Object.prototype.hasOwnProperty.call(dict, key) ? dict[key]
				: (Object.prototype.hasOwnProperty.call(ZH, key) ? ZH[key] : key);
			return tmpl(s, params);
		}

		/** 语言切换后重渲染（拿不到 subscribe 就退化成不响应）。 */
		function useLocaleRev() {
			const [rev, setRev] = React.useState(0);
			React.useEffect(function () {
				if (!localeSvc || typeof localeSvc.subscribe !== "function") return undefined;
				let dispose = null;
				try {
					dispose = localeSvc.subscribe(function () { setRev(function (n) { return n + 1; }); });
				} catch (e) { /* 忽略 */ }
				return function () {
					try { if (typeof dispose === "function") dispose(); } catch (e) { /* 忽略 */ }
				};
			}, []);
			return rev;
		}

		/** 从注入的 ctx 里判断是不是本机；判断不出来时按"不是"处理（fail closed）。 */
		function detectLoopback(ctx) {
			try {
				const remote = typeof ctx.get === "function" ? ctx.get("remote") : ctx.remote;
				const facts = remote && remote.$host;
				if (facts && typeof facts.isLoopback === "boolean") return facts.isLoopback;
			} catch (e) { /* 拿不到就 fail closed */ }
			return false;
		}

		// ────────────────────────────────────────────────────────
		// 面板
		// ────────────────────────────────────────────────────────

		const S = {
			wrap: { padding: "4px 2px", fontSize: 13, lineHeight: 1.6 },
			section: { marginTop: 18 },
			label: { display: "block", fontWeight: 600, marginBottom: 4 },
			hint: { opacity: 0.65, fontSize: 12, margin: "2px 0 6px" },
			input: { width: "100%", boxSizing: "border-box", padding: "6px 8px" },
			row: { display: "flex", gap: 8, alignItems: "center", marginTop: 10 },
			button: { padding: "6px 14px", cursor: "pointer" },
			status: { marginTop: 8, fontSize: 12, opacity: 0.75 },
			table: { width: "100%", borderCollapse: "collapse", fontSize: 12, marginTop: 6 },
			th: { textAlign: "left", padding: "4px 6px", borderBottom: "1px solid rgba(128,128,128,.35)" },
			td: { padding: "4px 6px", borderBottom: "1px solid rgba(128,128,128,.15)" },
			pre: { whiteSpace: "pre-wrap", wordBreak: "break-all", fontSize: 12 },
			title: { fontWeight: 700, fontSize: 15 },
		};

		function Line(props) {
			return h("p", { style: props.style ?? S.hint }, props.text);
		}

		function Section(props) {
			return h("div", { style: S.section }, props.children);
		}

		function Panel(props) {
			useLocaleRev();
			const rpcCall = props.rpcCall;

			const [state, setState] = React.useState({ status: "loading" });
			const [password, setPassword] = React.useState("");
			const [port, setPort] = React.useState("8080");
			const [busy, setBusy] = React.useState(false);
			const [note, setNote] = React.useState("");

			const load = React.useCallback(function () {
				Promise.all([
					rpcCall("remote.config.get"),
					rpcCall("remote.status"),
					rpcCall("remote.history.list"),
				]).then(function (r) {
					const cfg = r[0], st = r[1], hist = r[2];
					if (!cfg || !cfg.ok) {
						setState({ status: "error", error: (cfg && cfg.error) || null });
						return;
					}
					setPassword(cfg.value.password ?? "");
					setPort(String(cfg.value.port ?? 8080));
					setState({
						status: "ready",
						info: (st && st.ok) ? st.value : null,
						history: (hist && hist.ok && Array.isArray(hist.value)) ? hist.value : [],
					});
				}).catch(function (error) {
					setState({ status: "error", error: { message: String((error && error.message) || error) } });
				});
			}, [rpcCall]);

			React.useEffect(function () { load(); }, [load]);

			function save() {
				setBusy(true);
				setNote("");
				rpcCall("remote.config.set", { password: password, port: Number(port) })
					.then(function (r) {
						if (r && r.ok) {
							setNote(T("saved"));
							load();
						} else {
							setNote(T("saveFailed") + (r && r.error && r.error.message ? "：" + r.error.message : ""));
						}
					})
					.catch(function (error) {
						setNote(T("saveFailed") + "：" + String((error && error.message) || error));
					})
					.finally(function () { setBusy(false); });
			}

			// 出错就如实说，不装作没事
			if (state.status === "error") {
				return h("div", { style: S.wrap },
					h("div", null, T("loadFailed")),
					h("pre", { style: S.pre }, String((state.error && state.error.message) || "")));
			}
			if (state.status === "loading") {
				return h("div", { style: S.wrap }, "…");
			}

			const info = state.info;
			const history = state.history ?? [];

			return h("div", { style: S.wrap },
				h("div", { style: S.title }, T("title")),
				h(Line, { text: T("intro") }),

				h(Section, null,
					h("label", { style: S.label }, T("secPassword")),
					h(Line, { text: T("passwordHint") }),
					h("input", {
						style: S.input,
						type: "text",
						value: password,
						placeholder: T("passwordPlaceholder"),
						onChange: function (e) { setPassword(e.target.value); },
					})),

				h(Section, null,
					h("label", { style: S.label }, T("secPort")),
					h(Line, { text: T("portHint") }),
					h("input", {
						style: S.input,
						type: "number",
						min: 1,
						max: 65535,
						value: port,
						onChange: function (e) { setPort(e.target.value); },
					})),

				h("div", { style: S.row },
					h("button", {
						style: S.button,
						disabled: busy,
						onClick: save,
					}, busy ? T("saving") : T("save")),
					note ? h("span", { style: { fontSize: 12, opacity: 0.8 } }, note) : null),

				h("div", { style: S.status },
					info && info.running ? T("statusRunning", { port: info.port }) : T("statusStopped")),

				h(Section, null,
					h("div", { style: S.label }, T("secHistory")),
					history.length === 0
						? h(Line, { text: T("historyEmpty") })
						: h("table", { style: S.table },
							h("thead", null,
								h("tr", null,
									h("th", { style: S.th }, T("colTime")),
									h("th", { style: S.th }, T("colPlatform")),
									h("th", { style: S.th }, T("colAddress")))),
							h("tbody", null,
								history.slice().reverse().map(function (item, index) {
									const p = item && item.platform;
									const platform = p === "android" ? T("platformAndroid")
										: p === "ohos" ? T("platformOhos")
											: (p ? String(p) : "—");
									return h("tr", { key: String((item && item.at) || index) },
										h("td", { style: S.td }, formatTime(item && item.at)),
										h("td", { style: S.td }, platform),
										h("td", { style: S.td }, String((item && item.address) || "—")));
								})))),
			);
		}

		/**
		 * 非本机时只显示这一句 —— 与模型页逐字一致。
		 *
		 * ⚠️ 判断必须放在**渲染时**，不能在 apply 那一刻快照：
		 *    apply 早期 `ctx.get("remote")` 可能还没起来，那时判出来是 false，
		 *    就会**本机也永久显示"不可用"**。现判则服务一出现就恢复正常。
		 */
		function Gate(props) {
			if (!detectLoopback(props.ctx)) {
				return h("div", { style: S.wrap }, UNAVAILABLE_TEXT);
			}
			return h(Panel, props);
		}

		// ────────────────────────────────────────────────────────
		// apply
		// ────────────────────────────────────────────────────────

		/** slots：设置页那一栏需要；未注入时访问 ctx.slots 会被宿主拒绝。 */
		var inject = ["connection", "slots"];

		function apply(ctx) {
			// 语言服务是可选依赖：故意不写进 inject（inject 是硬依赖，缺了插件起不来）
			try {
				const svc = typeof ctx.get === "function" ? ctx.get("locale") : ctx.locale;
				if (svc && (typeof svc.getSnapshot === "function" || typeof svc.getLocale === "function")) {
					localeSvc = svc;
				} else {
					warnPlugin("locale 服务不可用，界面用中文");
				}
			} catch (e) {
				warnPlugin("locale 服务接不上，退回中文：" + String((e && e.message) || e));
			}

			if (typeof ctx.slots?.inject !== "function" || typeof ctx.slots?.register !== "function") {
				warnPlugin("没有槽位系统（宿主版本太老？），设置页那一栏不会出现");
				return;
			}

			function rpcCall(endpoint, payload) {
				return ctx.connection.rpc.call(CHANNEL, endpoint, payload ?? {});
			}

			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "webview-remote",
				order: 70,
				label: () => T("nav"),
				inject: () => ({ rpcCall: rpcCall, ctx: ctx }),
			}, Gate));
		}

		module.exports = { inject, apply };
		return module.exports;
	}
});
