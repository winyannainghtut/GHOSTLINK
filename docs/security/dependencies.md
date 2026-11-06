# Dependency scan, 2026-11-06

The scan found and fixed vulnerable locked dependencies before producing the final development packages. This is an advisory scan, not a comprehensive security audit.

- `govulncheck` 1.9.0, Go 1.26.10, worker build tag `with_gvisor`: initially reported five reachable HTTP/2 advisories in `golang.org/x/net` 0.57.0. Updated it to 0.62.0, Chi to 5.3.0, and `golang.org/x/crypto` to the advisory's fixed revision `v0.58.1-0.20261009181718-2f1f834330b2`, with compatible transitive modules. The final verbose scan reported **No vulnerabilities found**. Upstream sing-box protocol/library source remains unmodified. Go tests, vet, build and real-engine lifecycle/interoperability tests are rerun against the updated lock.
- After adding AmneziaWG, WireGuard and VLESS-REALITY (worker tags `with_gvisor,with_utls,with_wireguard`), `govulncheck` 1.9.0 reported two newly reachable advisories through uTLS certificate decompression: GO-2026-6888 in `github.com/andybalholm/brotli` 1.1.0 (excessive memory on crafted streams) and GO-2026-6865 in `github.com/klauspost/compress` 1.19.1 (panic on two-block frames). Updated them to 1.2.7 and 1.20.2; the rescan reported **No vulnerabilities found**, and the Go, real-engine and process suites passed again. sing-box and amneziawg-go source remain unmodified.
- For v0.3.0 the module also builds `ghostlink-server`. `govulncheck` 1.9.0 over `./...` (worker, server and all internal packages) reported **No vulnerabilities found**.
- New Rust dependencies for the pinned management client: `rustls` 0.23.46 with the `ring` 0.17.14 provider (TLS 1.3 only, no aws-lc), `tokio-rustls` 0.26.6, `hyper-rustls` 0.27.10 and `rustls-webpki` 0.103.16 through reqwest's `rustls-tls-manual-roots` feature. `rcgen` 0.13.2 is a test-only dependency, so no certificate fixture is committed.
- The server image base is pinned by digest: `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab` (index with amd64 and arm64). Re-pin it when distroless publishes security updates.
- `npm audit`: **zero known vulnerabilities** in the verification tooling dependency tree.
- `python scripts/audit-lockfiles.py`: queries OSV for **472** unique registry package versions in both Cargo locks, including non-Windows targets. Initially found eight OpenSSL advisory IDs; updated the root lock from `openssl` 0.10.75 / `openssl-sys` 0.9.111 to 0.10.82 / 0.9.118. Rescan removed those findings.

The Rust scan still returns three IDs covering two dependencies in the Linux desktop dependency chain:

| Package | Finding | Disposition |
|---|---|---|
| `glib` 0.18.5 | [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), alias [GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g): unsound `VariantStrIter` iteration | Fixed in glib 0.20.0. The current Tauri/GTK dependency chain uses 0.18; replacing its ABI-bound dependency directly is not a compatible lock update. Ghostlink does not call this iterator directly. Reachability through Linux dependencies has not been established. Linux GUI release remains pending dependency-chain upgrade or reviewed backport and Linux testing. |
| `proc-macro-error` 1.0.4 | [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html): unmaintained | Build dependency through GTK derive tooling; no fixed release. Track upstream replacement. This is a maintenance warning, not evidence of an exploited runtime vulnerability. |

These GTK dependencies are not compiled into the Windows application. The all-target Rust scan intentionally returns nonzero while the findings remain; there is no hidden ignore list. It checks lockfile version matches, not call reachability, system OpenSSL, drivers, WebView2 Runtime, external OpenVPN or the separately obtained local test peer. Keep those system components patched and review each target before distribution.

Local scan reports are under ignored `artifacts/rust-vulnerability-scan.json` and `artifacts/go-vulnerability-scan.txt`. Commands:

```powershell
python scripts/audit-lockfiles.py
npm audit
Push-Location core/outline-worker
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -tags with_gvisor,with_utls,with_wireguard -show verbose ./...
Pop-Location
```

OSV API: https://google.github.io/osv.dev/post-v1-querybatch/ . The scan sends only public registry package names and versions, with no source or credentials.
