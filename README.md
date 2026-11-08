# Finch 🦜

A compact, Burp Suite style **intercepting HTTP(S) proxy** for security testing, written in Rust.

| Layer | Technology |
|---|---|
| UI | [egui](https://github.com/emilk/egui) 0.37 (glow backend, system fonts) |
| HTTP engine (Repeater / Intruder) | [hyper](https://github.com/hyperium/hyper) 1.x + hyper-rustls |
| MITM proxy | **embedded engine** (`src/mitm`, extracted from [slinger-mitm](https://github.com/emo-crab/slinger)) with rustls + auto CA |
| Async runtime | tokio |

The release build is a single portable executable (`target/release/finch.exe`) tuned for
small size: `opt-level = "z"`, fat LTO, one codegen unit, stripped symbols, abort-on-panic.

## Features

- **Proxy ▸ Intercept** — pause requests, responses **and WebSocket messages** in flight,
  edit the raw bytes, then **Forward** or **Drop**, exactly like Burp. Queue counter,
  "Drop all", editable Raw view with right-click function menu.
- **Proxy ▸ HTTP history** — Burp-style table with sortable columns and a live filter
  (`text`, `status:404`, `host:example.com`, `mime:json`). Follow-new-traffic mode,
  a resizable request/response split viewer (Raw / Headers / Hex / JSON-pretty), row
  right-click actions, and **Send to Repeater / Intruder / Decoder / Comparer**.
- **Proxy ▸ WebSockets** — WS sessions and frames captured in real time (handshakes are
  also logged in HTTP history as `websocket`); per-message interception with edit/drop,
  RFC6455-compliant re-masking of rewritten client frames.
- **Proxy ▸ Options** — intercept toggles + URL substring filter, listener status,
  upstream proxy (HTTP / SOCKS5 / SOCKS5h), **host blacklist** (regex), CA export,
  launch browser via proxy, history limit.
- **Proxy ▸ TUN** — one-click virtual-adapter capture (Windows): routes IPv4 through a
  wintun adapter, lists every process with active network sockets (PID / name) and lets
  you **hijack per process with one click**; hijacked flows are pushed through the proxy
  for full interception/history with a `Process` column, everything else (incl. UDP/DNS)
  is relayed directly via the physical interface. Requires administrator; `wintun.dll` is
  downloaded automatically on first enable.
- **Target ▸ Site map** — host → path tree built from captured traffic, scope host list
  with "only in-scope" filtering, per-entry viewer.
- **Repeater** — edit and resend raw requests through the **hyper** engine (http/https),
  response viewer, request history, latency/size readout.
- **Intruder** — Burp-style attack workbench: mode dropdown (Sniper / Battering ram /
  Pitchfork / Cluster bomb), Target URL with "Update Host header" option, §-position
  marking (Add § / Clear § / Auto §) in a syntax-highlighted request editor with a
  search/highlight status bar, payload lists (paste / dictionary files / built-in lists /
  deduplicate), and **payload processing rules** reusing the Decoder op pipeline.
  Results open in a detail window (status/length/time + raw exchange viewer).
- **Decoder** — CyberChef-style recipe pipeline: URL / Base64 / Hex / HTML-entity,
  MD5 / SHA family, AES / DES / 3DES / SM4 / RC4, JWT decode/sign/verify.
- **Comparer** — line diff between two texts with color highlighting.
- **Settings** — listener port + restart, upstream proxy, CA export/copy, Intruder
  concurrency, data locations. Settings persist to `finch-data/finch.json`.

### Host blacklist

**Proxy ▸ Options ▸ Host blacklist** accepts one regular expression per line:

```
.*\.evil\.com
(^|\.)tracker\..*
^ads[0-9]*\.example\.com$
```

Matching **CONNECT tunnel targets** (port stripped) and **plaintext request hosts** are
refused with `403 Forbidden` before any connection to the origin is made. Invalid
patterns are reported and skipped on apply. The list persists in `finch.json`.

## Building

```bash
cargo build --release
```

The binary and its runtime data (CA, settings) are written next to the executable:

```
target/release/finch.exe
target/release/finch-data/
├── ca/ca_cert.pem, ca_key.pem   # auto-generated root CA (persist across runs)
└── finch.json                   # settings (incl. host blacklist)
```

## Usage

1. Run `finch.exe` — the proxy listens on **127.0.0.1:8080** by default.
2. Point your browser at the proxy (or click *Proxy ▸ Options ▸ Open browser via proxy*).
3. For HTTPS, export the CA (*Proxy ▸ Options ▸ Export CA certificate...*) and trust it:
   - Windows (current user): `certutil -addstore -user Root ca.pem`
   - Firefox: import in Settings ▸ Privacy ▸ Certificates ▸ Authorities.
4. Flip **Intercept is on** in the Proxy tab to hold requests; edit and Forward/Drop.

## CI/CD

- **CI** (`.github/workflows/ci.yml`) — build + `cargo test` on Linux, Windows and macOS
  for every push / pull request.
- **Release** (`.github/workflows/release.yml`) — pushing a `v*` tag builds release
  binaries for `x86_64-linux`, `x86_64-windows`, `x86_64-macOS`, `aarch64-macOS` and
  attaches the archives to the GitHub release:

  ```bash
  git tag v0.1.0 && git push origin v0.1.0
  ```

## Tests

End-to-end tests spin up the embedded MITM engine with the Finch interceptor plus local
test servers, and verify: HTTP capture, intercept + edit + forward, drop, response
tampering, WebSocket capture / per-message edit / drop, and the regex host blacklist
(403 for blocked hosts, pass-through otherwise):

```bash
cargo test
```

## Architecture notes

- `src/mitm/` is the MITM engine, extracted from slinger-mitm into the project and
  trimmed to what Finch uses (SOCKS5 server-side support and unused helpers dropped;
  WebSocket takeover added). `server.rs` handles CONNECT, TLS interception (dynamic
  per-host certificate minting), plaintext HTTP, raw TCP tunnels and WebSocket upgrades.
- `src/interceptor.rs` implements the engine's `Interceptor` trait; each request/response
  is converted to raw bytes, recorded into the history and — when intercepting is
  enabled — parked on a `tokio::oneshot` until the UI decides. WebSocket frames flow
  through `intercept_ws_message` (edit returns a new payload, `None` drops the message).
- Edited messages are re-parsed with `httparse` and rebuilt into `slinger::Request`/
  `Response` structures (Content-Length auto-corrected; origin-form targets absolutized).
- `src/ui/viewer.rs` hosts the reusable message viewer (Raw / Headers / Hex / JSON tabs,
  right-click Copy / Save / Send-to menu) shared by Intercept, History, WebSockets,
  Repeater, Intruder and Target.

## Known limitations

- Chunked *request* bodies are not fully parsed by the HTTP reader (Content-Length
  bodies are, which covers typical browser traffic).
- No Match & Replace rules, no CSRF token extraction — planned for later milestones.

## License

MIT (this project). Note that slinger is GPL-3.0 — linking it at runtime makes the
combined work subject to GPL-3.0 as well.
