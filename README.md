# dsh-webview-remote

**Safely connect to your DSH from a phone app.**

*[中文版](README.zh.md)*

The app is **WebView-driven** — **DSH's page looks exactly the same inside the app as it does
anywhere else**, and third-party plugins' UI renders normally too.

Two halves:

| | |
|---|---|
| [`Server/`](Server/) | The **DSH plugin** — an authenticated reverse proxy plus one panel in DSH's Settings |
| [`Client/`](Client/) | The **Flutter app** (Android + HarmonyOS) — a WebView shell |

## How it works

```
phone ──(one password)──▶ Server, listening on 0.0.0.0:<port>
                             │  attaches DSH's own launch token
                             ▼
                          DSH on 127.0.0.1
```

## Quick start

1. **Install the plugin** — from DSH's plugin panel, install `@nszzj/dsh-webview-remote-server`
2. **Settings → "WebView Remote"** — set an access password and a listen port, then Save.
   The status line should read "**Listening on 0.0.0.0:<port>**"
3. **Install the app** — download it from [Releases](../../releases/latest) and enter the same
   address and password there. (A phone browser cannot get in: the password goes in a request
   header, and there is no login page.)

## ⚠️ Security — read this before turning it on

| | |
|---|---|
| **The password is the only boundary** | Whoever holds it can **run commands on that machine** — that is what DSH is. |
| **Zero exposure by default** | With no password set, the plugin **does not listen at all** (not "listening and rejecting" — it never calls `listen`). |
| **Plain HTTP** | The password and all traffic can be sniffed on the LAN. **Do not enable this on an untrusted network** (cafés, hotels, guest Wi-Fi). |
| **Never map it to the internet** | No port forwarding, no frp, no ngrok. |
| **No management surface** | A remote client cannot see DSH's Models settings page, and this plugin's configuration form only renders on the local machine — a **UI gate**, not a security boundary. |

## Repository layout

```
Server/           the DSH plugin (also published to npm)
Client/           the Flutter app for Android and HarmonyOS
README(.zh).md    the file you are reading
```

## License

This repository is under the [MIT License](LICENSE).

The open-source licenses of the third-party software used by the client app are built into the
app's own "License" page — tap the "Open-source licenses" button to open it.
