# APKWatchtower (PS02)

A static (+ optional dynamic) security analyzer for Android APKs.
Upload an APK, get exported-component findings, hardcoded-secret
detection, Network Security Config review, insecure storage/logging
heuristics, a weighted risk score, and an HTML/PDF report.

## Architecture

```
Browser (Bootstrap + vanilla JS)
        │  multipart/form-data upload
        ▼
FastAPI backend  (app/main.py)
        │
        ▼
pipeline.run_pipeline()  ── single AnalyzeAPK() pass, reused everywhere
        │
        ├── analyzer/manifest_analyzer.py   exported components, dangerous flags, permissions
        ├── analyzer/secret_scanner.py      regex + entropy secret detection (resources + DEX strings)
        ├── analyzer/nsc_analyzer.py        Network Security Config XML analysis
        ├── analyzer/storage_logging.py     Log leakage, WebView, TrustManager, crypto, storage heuristics
        ├── dynamic/dynamic_analysis.py     optional: adb install + logcat capture + same secret rules
        └── analyzer/risk_engine.py         severity weighting → 0-100 score + rating band
        │
        ▼
SQLite (app/db/models.py)  ── scan history + findings
        │
        ▼
reporting/report_generator.py  ── Jinja2 → HTML, WeasyPrint → PDF
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Native dependency note:** WeasyPrint (used only for the `/report.pdf`
endpoint) needs Cairo/Pango/GdkPixbuf on the host. If you don't need
PDF export, the app still works fine -- `/report.html` has no native
dependency, and the PDF endpoint fails gracefully with a clear error
if WeasyPrint's native libs are missing rather than crashing the app.

```bash
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000/ and drag an `.apk` onto the upload panel.

## API

| Method | Path                          | Purpose                                   |
|--------|-------------------------------|--------------------------------------------|
| POST   | `/api/scan`                   | Upload + analyze an APK (`file`, optional `dynamic=true`) |
| GET    | `/api/scans`                  | Scan history summary list                 |
| GET    | `/api/scans/{id}`              | Full findings for one scan                |
| DELETE | `/api/scans/{id}`              | Remove a scan and its findings            |
| GET    | `/api/scans/{id}/report.html`  | Rendered HTML report                      |
| GET    | `/api/scans/{id}/report.pdf`   | Rendered PDF report                       |

```bash
curl -F "file=@sample.apk" http://localhost:8000/api/scan
curl -F "file=@sample.apk" -F "dynamic=true" http://localhost:8000/api/scan
```

## What each module checks

**Manifest / exported components** (`manifest_analyzer.py`)
- `android:debuggable`, `android:allowBackup`, `android:testOnly`
- `usesCleartextTraffic` (explicit and legacy-targetSdk implicit default)
- Missing `networkSecurityConfig`
- Every `activity` / `activity-alias` / `service` / `receiver` /
  `provider` is checked against Android's *actual* export resolution
  rule (explicit `android:exported` wins; otherwise a component with
  an `intent-filter` is implicitly exported) -- not just a naive
  attribute read. Exported providers without a `permission` are
  flagged Critical (data leak / injection surface); other exported
  components without a permission are High.
- Dangerous permission inventory.

**Hardcoded secrets** (`secret_scanner.py`)
- Curated signatures: AWS keys, Google API keys, Firebase, Slack,
  Stripe, GitHub tokens, JWTs, PEM private keys, Basic-Auth URLs,
  generic `password=`/`api_key=` assignments.
- Shannon-entropy screening for long base64/hex-looking string
  literals that don't match a known signature, to catch unlabelled
  secrets a fixed regex list would miss.
- Scans both `res/values/strings.xml`-style resource strings **and**
  the DEX constant-pool (so secrets hardcoded directly in
  Java/Kotlin, not just externalised to resources, are caught).
- Noise filtering (`example`, `test`, `placeholder`, ...) and
  redacted evidence in reports (never prints the full secret).

**Network Security Config** (`nsc_analyzer.py`)
- Locates and decodes the binary XML file referenced by
  `android:networkSecurityConfig`.
- `base-config`/`domain-config` `cleartextTrafficPermitted` review.
- `trust-anchors src="user"` detection (MITM-proxy trust risk).
- `pin-set` detection (reported as a positive/Info finding).
- `debug-overrides` present in a shipped APK.

**Storage / logging / crypto heuristics** (`storage_logging.py`)
- Log calls adjacent to sensitive-looking identifiers (password,
  token, secret, session, ...) -- flagged as a heuristic, not a
  confirmed dataflow finding.
- WebView `setJavaScriptEnabled` + `addJavascriptInterface` (RCE
  bridge), permissive file-access flags.
- Custom `TrustManager.checkServerTrusted()` / `HostnameVerifier.verify()`
  implementations that trivially accept everything (SSL bypass).
- ECB cipher mode usage.
- SQLite usage without SQLCipher (likely-unencrypted local DB).
- `MODE_WORLD_READABLE`/`WRITEABLE`-shaped file mode usage.

**Optional dynamic analysis** (`dynamic_analysis.py`)
- `adb install` → launch via monkey → capture logcat for a
  configurable window → apply the *same* secret-detection rules to
  runtime log output → uninstall.
- Fully optional and safely skipped (reported as an Info finding,
  never blocks the static report) if no emulator/device is attached.
- Deliberately scoped to `adb`/`logcat` only, per the challenge's
  "organizer-provided emulators only" constraint -- no Frida/
  instrumentation dependency.

**Risk scoring** (`risk_engine.py`)
- Severity → weight: Critical=10, High=6, Medium=3, Low=1, Info=0.
- Per-category score is capped before summing, so a flood of
  low-severity noise in one category can't mathematically outweigh a
  single Critical elsewhere.
- Normalized to a 0-100 score with Critical/High/Medium/Low/Info
  rating bands.

## Extensibility

- **New secret pattern:** add a tuple to `SIGNATURES` in
  `secret_scanner.py` -- automatically applies to both static and
  dynamic (logcat) scanning since `dynamic_analysis.py` imports the
  same list.
- **New manifest check:** add to `analyze_manifest()`; just append a
  `Finding(...)`.
- **New storage/crypto heuristic:** add a pattern check inside the
  method-iteration loop in `storage_logging.py`.
- **New severity/weight tuning:** edit `SEVERITY_WEIGHTS` /
  `RATING_BANDS` / `CATEGORY_CAP` in `risk_engine.py` only.
- **Swap the report look:** edit `app/templates/report.html` --
  HTML and PDF share the exact same template.

## Known limitations

- Log-leak and insecure-file-mode heuristics are text/bytecode
  *proximity* checks, not real dataflow analysis -- they flag
  candidates for manual review rather than confirmed vulnerabilities.
  This is called out explicitly in each such finding's description.
- Entropy-based secret detection will surface some false positives
  on legitimately random-looking non-secret strings (resource hashes,
  encoded images, etc.); it's intentionally Low severity for that
  reason.
- Dynamic analysis captures logcat only; it does not proxy/inspect
  network traffic. Pairing this scanner's static Network Security
  Config findings with a proxy tool (mitmproxy/Burp) against the same
  emulator remains a manual step outside this tool's current scope.
- Heavily obfuscated (e.g. R8/ProGuard-renamed classes, string
  encryption) APKs will reduce the accuracy of keyword-based
  heuristics; signature-based secret detection is unaffected since it
  matches on value, not identifier names.
