# @nszzj/dsh-webview-remote-server

**A password-protected LAN entry point for DSH** — let a phone or tablet use your DSH over the LAN, without exposing it to the internet.

DSH itself only talks to the local machine: its web server binds to loopback and it checks where requests come from. This plugin stands in the middle. The phone connects to the plugin's port, clears one password, and the plugin knocks on DSH's door **carrying DSH's own launch token**.

> The client — a Flutter app for Android and HarmonyOS — is at
> **[github.com/ns-zzj/dsh-webview-remote](https://github.com/ns-zzj/dsh-webview-remote)**.
>
> **There is no web login page, so a browser cannot get in.** The password travels in a request
> header (`X-Gateway-Password`), which an address bar cannot send; a browser pointed at the port
> just gets a bare `401` with nothing to fill in. That is deliberate — see the comments at the
> top of `lib/gateway.js`. **The client app is the way in from a phone.**

---

## What it is

| | |
|---|---|
| Role | A **host-side DSH plugin**: an authenticated reverse proxy plus one panel in DSH's Settings |
| What it does | The phone opens `http://<your computer's LAN IP>:<port>/`, enters the password once, then uses DSH as usual |
| How it works | The plugin listens on `0.0.0.0:<port>`, forwards to `127.0.0.1:<DSH's real port>`, and attaches DSH's launch token |
| Authentication | **One password**, sent in a request header (never in the URL) |
| Configuration | DSH Settings → left sidebar → "WebView Remote" |
| Data | `$DSH_HOME/webview-remote-server/` (see below) |
| **Not** | Not a tunnel, not a public deployment, not a VPN |

---

## ⚠️ Security first — please read before installing

| | |
|---|---|
| **The password is the only boundary** | Whoever holds it can **run commands on this machine** — that is what DSH is. Treat it as handing over a shell on this computer. |
| **Zero exposure by default** | With no password set, the plugin **does not listen at all**. Not "listening and rejecting" — it never calls `listen`. |
| **Once it starts** | It listens on `0.0.0.0`, so **every device on the same LAN** can reach that port. |
| **Plain HTTP** | The password and all traffic can be sniffed on the LAN. **Do not enable this on an untrusted network** (cafés, hotels, guest Wi-Fi). |
| **Never map it to the internet** | No port forwarding, no frp, no ngrok, nothing of that kind. |

**The management surface.** A remote client **cannot see** the Models settings page and its like. That is DSH's own behaviour: when the page hostname is not a loopback address, DSH's settings mirror enters an "unavailable" state. This plugin's own configuration panel behaves the same way — **it only renders the form when DSH is running on the local machine.** That is a UI gate, not access control; see the note under Known limitations.

---

## Installation

| Step | Do this |
|---|---|
| 1 | Install `@nszzj/dsh-webview-remote-server` from DSH's **plugin panel** |
| 2 | **Fully quit DSH and open it again** |

> The first install needs no restart; **updates** (reinstalling a newer version) do. Host-side changes only take effect after a restart.

---

## Quick start

1. DSH **Settings** → left sidebar → "**WebView Remote**"
2. **Access password** — set one (do not reuse a password from anywhere else)
3. **Listen port** — pick a port for the gateway (default `8080`; change it if it is taken)
4. Click **Save**. The status line becomes "**Listening on 0.0.0.0:<port>**"
5. On the phone — install the client, then enter `your computer's LAN IP:port` and the password.
   (A phone browser cannot get in — see the note at the top.)
6. Back in that panel, "**Connection history**" should have gained an entry

> On Windows, find your LAN IP with `ipconfig` and look for `IPv4 Address` (usually `192.168.x.x`).

---

## What the panel contains

| Item | Notes |
|---|---|
| Access password | Stored in plain text in a local config file (see below). Empty = stop listening |
| Listen port | Saving restarts the listener **immediately** — no DSH restart needed |
| Status | "Listening on 0.0.0.0:port", or "Not started (no password yet)" |
| Connection history | The most recent **200** entries: **time / platform / address** |

**Why the "platform" column may show `—`.** It comes from a request header the client sends
voluntarily, and the client app always sends it (Android / HarmonyOS). Anything else you point at
the port — a script of your own, say — may not, and then that entry stays empty.

**When an entry is written.** Only at the moment the **password check succeeds**. Attempts with a wrong password are **not** recorded.

---

## Where the data lives

```
$DSH_HOME/webview-remote-server/
├── config.json     password / port / historyLimit
└── history.json    connection history, at most 200 entries (oldest dropped)
```

- `$DSH_HOME` is DSH's home directory — on Windows, usually `C:\Users\<you>\.dsh`
- **`password` is plain text** — an ordinary string in a local file. Not encrypted, not obfuscated.
  - This is deliberate: it is a local file and remotes cannot read it; encrypting it would be false comfort.
  - If that bothers you, simply do not reuse a password you use elsewhere.
- **Deleting the whole `webview-remote-server` directory** returns you to a "never installed" state — configuration and history both gone.

---

## Known limitations

- **One instance per machine.** The listen port must be free; it fails to start if an old standalone gateway script is holding the same port
- **Plain HTTP.** Moving to HTTPS means a self-signed certificate plus installing a CA on the phone — this plugin does not do that for you
- **The platform column depends on the client reporting it.** The client app always does; anything you write yourself may not
- **Host-side changes require fully quitting and reopening DSH.** Browser-side changes only need a page refresh
- **The configuration form only renders on the local machine — that is a UI gate, not access control.** The RPC endpoints behind it are open to any connected client, so a remote one can change the password or port by calling them directly. It is not a privilege escalation — a remote client is already authenticated and can run commands on the host — but it **can lock you out**. Do not mistake a hidden form for a boundary
- **Failed authentications are not recorded** in the history

---

## Package layout

```
lib/index.js          host half: config, history, RPC endpoints, listener lifecycle
lib/gateway.js        the gateway itself: authentication, token injection, in-page shim
client/client.js      client half: the Settings panel (plain JS, no build step)
cordis.patch.yml      DSH plugin manifest — `id` and `name` are two different things,
                      see the comments inside the file
```

**Zero dependencies.** Nothing outside Node's built-in modules is bundled. The client half
pulls React from DSH's own module loader at runtime; it is not shipped in this package.

**The token is never written to disk.** The gateway and DSH live in the same process, so it asks `connection.authenticatedUrl()` for a token whenever it needs one. That removes the whole "stale token file" class of problem.
