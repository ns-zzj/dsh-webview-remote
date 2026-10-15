# dsh-webview-remote — Client

**The phone app.** A WebView shell around DSH: enter the gateway address and password once,
then use the full DSH web UI on your phone. Android and HarmonyOS.

It talks to the plugin in [`../Server/`](../Server/) — that has to be installed and running on
your computer before this app is useful.

## How it connects

1. `GET /__gateway/session` with the password in the **`X-Gateway-Password`** header, plus
   `X-Client-Platform: android|ohos`
2. The gateway answers `204` and sets a `dsh-gw` cookie; the app hands that cookie to the WebView
3. The app loads `http://<address>/` and waits for DSH's `#root` to appear

The password only ever travels in a request header — **never in the URL**.

## Requirements

| | |
|---|---|
| **Flutter-OHOS SDK** | this project builds both Android and HarmonyOS; an ordinary Flutter SDK has no HarmonyOS target |
| **DevEco Studio** | for building and signing the HarmonyOS HAP, and for getting it onto a device |
| **Android SDK** | for the Android APK |

## Dependencies come from git

`pubspec.yaml` pulls the OpenHarmony-adapted packages from their **git sources** rather than
pub.dev — the published versions there do not support Dart 3
(`flutter_secure_storage_ohos` 1.0.0 declares `sdk: ">=2.19.6 <3.0.0"`).

So the first resolve needs network access to those git hosts:

```bash
flutter pub get
```

If you would rather use your own local checkouts, replace each `git:` block with a `path:`
entry — that is what the original development tree does.

## Build

| Target | Command |
|---|---|
| HarmonyOS | `flutter build hap` — or open `ohos/` in DevEco Studio and build there |
| Android | `flutter build apk` |

## Signing is yours to set up

**This repository contains no signing configuration** — deliberately. The original had the
author's certificate paths and passwords in `ohos/build-profile.json5`, which must not be public.
hvigor and DevEco will tell you plainly that nothing is signed.

- **HarmonyOS** — DevEco Studio → File → Project Structure → Signing Configs → enable
  *Automatically generate signature* and sign in with a Huawei account.
- **Android** — use your own keystore (plus a `key.properties`), or let Flutter fall back to the
  generated debug key for local testing.

An unsigned HAP cannot be installed on a device at all — whoever wants it has to sign it first.

## Known limitations

- **Plain HTTP** — anyone on the same LAN can sniff the password
- **The app is a thin shell** — every DSH feature comes from the page it loads; the app itself
  only does the login, the cookie, and some viewport workarounds

## Tests

```bash
flutter test
```

One smoke test: the connect form renders, and the password field is masked.
