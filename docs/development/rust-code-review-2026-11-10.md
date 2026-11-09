# Rust review: Ghostlink

Ghostlink's Rust code implements the local privileged VPN daemon, protocol credential validation, worker lifecycle, typed IPC, CLI, restricted MCP bridge, and Tauri desktop shell. This is application code with internal library crates, so this review applies application simplicity rules rather than assuming a published general-purpose library API. The most important fix is to prevent explicit OpenVPN routes from bypassing the Unix full-tunnel authorization policy. The review found two correctness issues to fix, three maintenance issues worth addressing, and one documentation improvement. Formatting, Clippy, tests, and rustdoc were run; the standard tests pass, but additional probes reproduce both correctness issues.

## Review scope and method

- **Tooling:** BeautifulRust v1.6.0, using its rust-review skill, rust-best-practices skill, and bundled rule digests. The plugin's remote MCP service was not needed; repository source was read locally.
- **Final reviewed revision:** v0.8.5, commit `008ecf86d1923219f09056c63f36b20da1d100a0`.
- **Concurrent work:** The review began at v0.8.4 (`05daf2a`). Another change advanced the checkout to v0.8.5 during the review. Comparing the Rust source between those revisions showed only the worker version-string change. The final unit tests, Clippy runs, and opt-in traffic tests used v0.8.5.
- **Crates:** `ghostlink-engine`, `ghostlink-contracts`, `ghostlinkd`, `ghostlink`, `ghostlink-mcp`, and the separate `ghostlink-desktop` workspace.
- **Edition and MSRV:** Rust 2021. The workspace declares Rust 1.92, but its members do not inherit that declaration; see finding 5.
- **Frameworks:** Tokio and Tauri. No Bevy-specific rules apply.
- **Boundaries:** No production Rust code was changed. The Go findings from the earlier reviews are outside this report. Suggested code below is review guidance, not an applied or fully integrated patch.

## Must fix

### 1. Explicit OpenVPN default routes bypass the full-tunnel policy (`core/vpn-engine/src/profile.rs:218`)

**Priority:** P1  
**Rule:** Validate inputs and encode their actual meaning in types: **C-VALIDATE**, Rust API Guidelines; **Item 1**, Effective Rust; BeautifulRust, *Types and API design*.

**Locations:** [route parsing](../../core/vpn-engine/src/profile.rs#L218), [summary classification](../../core/vpn-engine/src/profile.rs#L311), and [Unix authorization check](../../services/vpn-daemon/src/main.rs#L422).

**Problem:** The parser sets `full` only when it sees `redirect-gateway`. It accepts and preserves explicit `route` directives without including their coverage in `summary.tunnel_mode`. The Unix daemon then uses that summary string to decide whether `--allow-full-tunnel` is required.

A valid inline profile containing these routes is accepted and classified as `split`:

```text
route 0.0.0.0 128.0.0.0
route 128.0.0.0 128.0.0.0
```

Together these routes cover every IPv4 destination. OpenVPN documents the same two prefixes as the mechanism used by `redirect-gateway def1`. [OpenVPN 2.6 manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/).

**Consequence:** A profile can carry the equivalent of full IPv4 routing while bypassing the administrator's full-tunnel check. This can disrupt remote administration on Unix. It also gives the UI an incorrect tunnel-mode summary.

**Evidence:** A separate Rust probe generated disposable certificates, validated this profile through the real `profile::validate`, confirmed both routes survived canonicalization, and asserted that the summary must be `full`. It failed with:

```text
left:  "split"
right: "full"
```

An ordinary private-subnet route remained `split` in a passing control test. No OS routes were installed. The parser error was reproduced on Windows; its effect on Unix authorization follows from the daemon's checked code path.

**Fix:** Classify the effective VPN-directed route coverage as well as `redirect-gateway`. Reuse the interval-union approach already present in `WgConfig::full_tunnel`; do not recognize only the literal `/0` or the two `/1` strings, since four `/2` routes can have the same effect. Exclude routes explicitly directed through `net_gateway` and validate contiguous netmasks.

The integration should keep the original redirect directive separate from the effective authorization classification:

```rust
// In the existing route branch, after parsing and validating the arguments:
let network = u32::from(args[0].parse::<std::net::Ipv4Addr>()?);
let mask = args.get(1)
    .map(|value| value.parse::<std::net::Ipv4Addr>())
    .transpose()?
    .map(u32::from)
    .unwrap_or(u32::MAX);
ensure!(mask.leading_ones() + mask.trailing_zeros() == 32,
        "Invalid IPv4 netmask");
if args.get(2).is_none_or(|gateway| gateway != "net_gateway") {
    vpn_ranges.push((network & mask, (network & mask) | !mask));
}

// After parsing: extract the shared coverage helper from WgConfig::full_tunnel.
let requires_full_tunnel = full || covers_public_ipv4(&vpn_ranges);

// Use this for the summary and authorization, while `full` still controls
// whether the original redirect-gateway directive is emitted.
tunnel_mode: if requires_full_tunnel { "full" } else { "split" }.into(),
```

Here `vpn_ranges: Vec<(u32, u32)>` is collected during parsing, and `covers_public_ipv4` is the proposed shared helper extracted from the existing WireGuard coverage algorithm. These excerpts are not a standalone patch.

**Regression coverage:** Explicit `/0`, paired `/1`, four `/2`, private-subnet routes, `net_gateway` exclusions, and the daemon's refusal without `--allow-full-tunnel`.

### 2. An abnormal worker exit before `started` does not activate the cleanup barrier (`core/vpn-engine/src/worker_session.rs:433`)

**Priority:** P1  
**Rule:** Preserve actionable failure information: BeautifulRust, *Error handling*; use types to distinguish failure states: **Item 1**, Effective Rust.

**Locations:** [worker exit classification](../../core/vpn-engine/src/worker_session.rs#L433), [cleanup barrier](../../services/vpn-daemon/src/main.rs#L330), and [worker startup-event handling](../../core/vpn-engine/src/worker_session.rs#L361).

**Problem:** A non-successful worker exit becomes `network_cleanup_unverified` only when `initialized` is true. That flag is set after a valid `started` event is received and checked. A process can fail after privileged initialization begins but before that event reaches the daemon.

In that case the daemon retains an ordinary engine-exit error instead of either cleanup-uncertainty code. `cleanup_failure()` recognizes only the uncertainty codes, so a later connection is not blocked pending inspection. The forced-kill timeout path already takes the more conservative approach regardless of `initialized`.

**Consequence:** The code can allow another tunnel start after an abnormal startup exit without evidence that route, DNS, or filter cleanup completed. A leftover network configuration was not demonstrated by this review; the demonstrated defect is the missing uncertainty classification.

**Evidence:** A separate helper executable implemented the pinned worker identity and successful `check`, then exited with status 23 from `run` without emitting `started`. It changed no network settings. A probe waited for the real Rust session task to finish and observed:

```text
Some("outline_engine_exited_check_service_permissions")
```

The assertion requiring a cleanup-uncertainty code failed.

**Fix:** Default an abnormal or unreadable worker exit to cleanup uncertainty, including during startup. A minimal conservative change is:

```rust
Ok((false, Ok(status))) if status.success() => {}
Ok((false, _)) => {
    reason = Some("network_cleanup_unverified");
}
```

This deliberately errs on the side of requiring inspection. To avoid unnecessary barriers for explicitly reported, clean pre-initialization failures, represent worker termination evidence with an enum and exempt only protocol outcomes that guarantee no network mutation or completed cleanup. Do not infer that guarantee from the absence of `started`.

**Regression coverage:** Nonzero exit before `started`, explicit stop racing startup, reported cleanup failure, and a clean acknowledged startup failure.

## Should fix

### 3. `AdminError` does not implement the standard error trait (`core/vpn-engine/src/server_admin.rs:171`)

**Priority:** P2  
**Rule:** **C-GOOD-ERR**, Rust API Guidelines; **Item 4**, Effective Rust.

**Location:** [AdminError and its Display implementation](../../core/vpn-engine/src/server_admin.rs#L171).

**Problem:** Public administration methods return `Result<_, AdminError>`. The type implements `Debug` and `Display`, but not `std::error::Error`. It cannot satisfy generic error bounds or participate in ordinary `anyhow` error conversion and context without custom adaptation.

This is an internal API maintenance issue, not a current user-facing command failure. The current callers manually map its variants.

**Evidence:** A compile probe requiring `AdminError: std::error::Error` failed with E0277.

**Fix:** The current variants contain no wrapped source error, so this is sufficient:

```rust
impl std::error::Error for AdminError {}
```

Add a compile-time trait assertion in the tests:

```rust
fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
assert_error::<AdminError>();
```

Keep sanitized messages and the explicit variants. Implementing the trait does not require exposing credentials or raw network errors.

### 4. Unsafe platform code lacks explicit safety reasoning (`core/vpn-engine/src/storage.rs:164`)

**Priority:** P2  
**Rule:** **M-UNSAFE**, Microsoft Pragmatic Rust Guidelines; **clippy::undocumented_unsafe_blocks**; BeautifulRust, *Unsafe and FFI*.

**Locations:** [SID/token buffers](../../core/vpn-engine/src/storage.rs#L164), [pipe-server verification](../../packages/shared-contracts/src/lib.rs#L663), [TCP ownership inspection](../../core/vpn-engine/src/process.rs#L8), [OpenVPN peer inspection](../../core/vpn-engine/src/management.rs#L331), and [named-pipe construction](../../services/vpn-daemon/src/ipc.rs#L29).

**Problem:** The Windows FFI blocks perform pointer casts, variable-length buffer reads, and native allocation management without `SAFETY` explanations. Reviewers must reconstruct alignment, bounds, ownership, and lifetime requirements each time. The pedantic run also flags the two `Vec<u8>` to `TOKEN_USER` pointer casts for stricter target alignment.

**Evidence:** A focused Clippy pass reported nine missing-safety-comment diagnostics on the Windows build. This review did not establish exploitable undefined behavior; a missing comment alone is not proof of unsoundness.

**Fix:** Document the actual invariants, keep unsafe operations narrow, and use explicitly aligned storage for token information in both duplicated SID-reading paths. For example:

```rust
let words = (size as usize).div_ceil(std::mem::size_of::<usize>());
let mut data = vec![0usize; words];
// Pass data.as_mut_ptr().cast() and the byte count to GetTokenInformation.
// Check successful completion and the required output size before this read.

// SAFETY: data is sufficiently large and aligned for TOKEN_USER; the successful
// Win32 call initialized it, and data remains alive while its SID is inspected.
let own = unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid };
```

The omitted API call and size checks must remain part of the implementation. Use native-allocation guards where early returns could otherwise skip `LocalFree` or handle cleanup. Preserve the existing owner checks and remote-pipe rejection.

### 5. The declared Rust 1.92 minimum is not applied to the packages (`Cargo.toml:10`)

**Priority:** P2  
**Rule:** **M-MSRV** and **M-CARGO-WORKSPACE**, Microsoft Pragmatic Rust Guidelines.

**Locations:** [workspace package metadata](../../Cargo.toml#L10), [representative member manifest](../../core/vpn-engine/Cargo.toml#L1), and [separate desktop manifest](../../apps/desktop/src-tauri/Cargo.toml#L1).

**Problem:** `rust-version = "1.92"` appears under `[workspace.package]`, but none of the five members sets `rust-version.workspace = true`. The separate desktop package also omits `rust-version`. As a result, Cargo package metadata does not express the intended compiler minimum.

**Evidence:** `cargo metadata --no-deps --format-version 1` returned no `rust_version` for all five workspace packages. Workspace metadata requires explicit inheritance in each member. [Cargo workspace documentation](https://doc.rust-lang.org/cargo/reference/workspaces.html#the-package-table).

**Consequence:** Cargo cannot report the project's declared minimum as an early package requirement, and tooling that reads package MSRV receives no declared value. This review did not determine an alternative minimum compiler version.

**Fix:** In each workspace member:

```toml
[package]
rust-version.workspace = true
```

In the separate desktop package:

```toml
[package]
rust-version = "1.92"
```

Then assert the expected values in metadata and maintain a compiler-version check in CI if Rust 1.92 is intended to remain supported.

## Consider

### 6. Document failure contracts and remove the broken rustdoc link (`packages/shared-contracts/src/lib.rs:580`)

**Priority:** P3  
**Rule:** **C-FAILURE**, Rust API Guidelines; **M-CANONICAL-DOCS**, Microsoft Pragmatic Rust Guidelines; **clippy::missing_errors_doc** and **rustdoc::broken_intra_doc_links**.

**Locations:** [bounded IPC reads](../../packages/shared-contracts/src/lib.rs#L580), [private state-directory setup](../../core/vpn-engine/src/storage.rs#L26), [credential resolution](../../core/vpn-engine/src/access.rs#L99), and [CLI command documentation](../../cli/ghostlink/src/main.rs#L489).

**Problem:** Many internal public functions return `Result` without documenting meaningful failure categories. A focused Clippy run emitted 31 missing-`# Errors` diagnostics. Separately, rustdoc interprets `[PORTS]` in the CLI help comment as an unresolved item link.

These crates belong to one application, so this is documentation debt rather than a reason to redesign every public API or replace application-level `anyhow` errors.

**Fix:** Add concise failure contracts at security and lifecycle boundaries first:

```rust
/// Reads one newline-terminated frame, bounded by MAX_FRAME.
///
/// # Errors
/// Returns an error if the peer closes before a full frame, the frame exceeds
/// MAX_FRAME, or the underlying reader fails.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Vec<u8>> {
    // Existing implementation.
}
```

Use inline code for the CLI syntax:

```rust
/// Show the access rules, or replace them with
/// `--rule "FROM TO PROTOCOL [PORTS]"` (repeatable).
```

Group repeated documentation warnings rather than treating each function as a separate finding.

## What's already good

- The IPC and MCP surfaces use typed actions, reject unexpected fields, and keep agent grants narrower than owner administration. Credential import and server administration are not exposed as agent tools.
- Management TLS pins the certificate during the handshake and verifies handshake signatures before sending a URL containing the management secret. `ManagementKey` has a redacted `Debug` implementation; credential types deliberately avoid ordinary debugging output.
- Credential parsers bound input sizes, reject executable hooks and unsupported transports, and reconstruct engine configuration from validated fields. The dynamic Outline fetch validates destinations, pins DNS answers, and rejects redirects.
- The normal lifecycle already uses private-config ownership guards, explicit stop/wait behavior, and cancellation-aware framing. Existing tests cover malformed input, worker cleanup reports, certificate pinning, and encrypted protocol interoperability. Finding 2 concerns a specific abnormal-startup gap in that design.

The daemon's serialized connection changes and some guards held across asynchronous work are documented design choices in `agent.md`. They can delay status requests, but this report does not classify their mere presence as a new correctness defect. Likewise, secret-bearing types should not receive an unredacted derived `Debug` simply to satisfy a generic style rule.

## Validation results

| Check | Observed result |
| --- | --- |
| Root workspace and desktop `cargo fmt --check` | Passed |
| Root `cargo clippy --workspace --all-targets --all-features -- -W clippy::pedantic` | Completed successfully with warnings; not warning-clean |
| Separate desktop Clippy, all targets/features, pedantic | Completed successfully with warnings; not warning-clean |
| Focused safety-comment/error-documentation Clippy run | Completed; nine safety-comment and 31 error-documentation diagnostics, grouped above |
| Root workspace tests | 51 passed; six opt-in tests initially ignored |
| Separate desktop tests | 2 passed |
| Explicit opt-in worker/traffic run | All six passed with the freshly built v0.8.5 worker and pinned sing-box 1.14.4 peer |
| `cargo doc --workspace --no-deps` | Completed with one broken-link warning, included in finding 6 |
| Additional behavioral probes | One split-route control passed; the route-classification and abnormal-worker-exit assertions failed as described in findings 1 and 2 |
| Additional error-trait compile probe | Failed with E0277, confirming finding 3 |
| Package metadata inspection | All five workspace packages lacked a declared `rust_version`, confirming finding 5 |

Additional probes and logs are under `.tools/rust-review-20261110/`, outside tracked production source. They use disposable certificates, documentation IP addresses, and a worker helper that does not change networking. Their deliberate failures are separate from the passing project test suites.

The standard tools were run through `scripts/cargo.ps1` to initialize the Windows build environment. Representative commands:

```powershell
./scripts/cargo.ps1 fmt --all --check
./scripts/cargo.ps1 clippy --locked --workspace --all-targets --all-features -- -W clippy::pedantic
./scripts/cargo.ps1 test --locked --workspace
./scripts/cargo.ps1 doc --locked --workspace --no-deps

./scripts/cargo.ps1 fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
./scripts/cargo.ps1 clippy --locked --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --all-features -- -W clippy::pedantic
./scripts/cargo.ps1 test --locked --manifest-path apps/desktop/src-tauri/Cargo.toml
```

### Limits

- The six opt-in tests are proxy-mode tests. They do not demonstrate full-device routing, DNS/IPv6 leak prevention, or privileged cleanup after a real crash.
- The OpenVPN policy issue was reproduced at the parser boundary; a privileged Unix VPN session was not started.
- The abnormal-exit probe demonstrates error classification, not actual leftover routes or DNS configuration.
- Windows platform code was reviewed and linted; Linux-specific unsafe paths were inspected but not executed locally. Miri and fuzzing were not run.
- No production app/service, Docker daemon, host firewall, or cloud resources were used for this review. No source fixes or commits were made by this review.

## Suggested BeautifulRust lint configuration

The project currently has no inherited lint table. Consider adopting a selected subset of BeautifulRust's [lints.toml](https://github.com/morganlinton/BeautifulRust/blob/main/lints/lints.toml) and [clippy.toml](https://github.com/morganlinton/BeautifulRust/blob/main/lints/clippy.toml), rather than enabling every library-oriented rule at once.

For this application, an initial configuration could be:

```toml
# Root Cargo.toml
[workspace.lints.rust]
unsafe_op_in_unsafe_fn = "warn"

[workspace.lints.clippy]
undocumented_unsafe_blocks = "warn"
missing_errors_doc = "warn"

# Each workspace member Cargo.toml
[lints]
workspace = true
```

Add equivalent package-level settings to the separate desktop workspace. This would surface finding 4's undocumented unsafe blocks and finding 6's missing failure contracts automatically. It would not detect the routing-policy or worker-cleanup bugs; those need the behavioral regression tests described above. Keep warnings-as-errors in CI once the selected warnings are addressed, rather than adding `#![deny(warnings)]` to source.

## Resolution in v0.8.5

Added after the review, when the fixes shipped. The CHANGELOG's 0.8.5 section and the verification ledger have the details.

| # | Fix | Tests |
| --- | --- | --- |
| 1 | `route` lines are collected as IPv4 ranges (contiguous netmasks only; routes through `net_gateway` excluded) and the summary is `full` when `redirect-gateway` is set or they cover every public IPv4 address. The coverage walk is `wireguard::covers_public_ipv4`, now shared with WireGuard's AllowedIPs check. `full` alone still decides whether `redirect-gateway` is written, so the canonical profile is unchanged. Routes a server pushes are not covered; that limit is in `agent.md`. | `routes_that_cover_the_internet_are_a_full_tunnel` (`/0`, two `/1`, four `/2`, gateway forms, private routes, one `/1`, `net_gateway`, a netmask with gaps). Process test through the real service: import and `profile list` on both systems, and the refusal without `--allow-full-tunnel` on Linux; on Windows nothing is connected |
| 2 | The worker's status lines become a `Report` (nothing, a clean failure, a cleanup failure). `unverified_cleanup` asks for an inspection after any abnormal end, also before `started`, unless the worker reported a clean failure. | `abnormal_worker_exits_need_an_inspection`; `tests/worker_exit.rs` drives the real session with the test binary as a stand-in worker: an exit before `started` is blocked, a clean failure and a stop are not, a cleanup failure is. With the old rule put back, the exit before `started` gives `outline_engine_exited_check_service_permissions` and the test fails. The unprivileged process test confirms that the real worker's failed TUN start is not blocked, and the six opt-in real-engine tests pass |
| 3 | `impl std::error::Error for AdminError`. | `admin_errors_are_standard_errors` (`Send + Sync + 'static` bounds and `anyhow` conversion) |
| 4 | A `SAFETY` comment on all nine Windows blocks and the Unix ones (`geteuid` moved into `storage::effective_uid`, plus `chown`). Both `TOKEN_USER` reads use `usize`-word buffers. `undocumented_unsafe_blocks` and `unsafe_op_in_unsafe_fn` are in the lint tables; CI's `clippy -D warnings` enforces them. | Clippy clean on Windows with the lint; Linux in CI |
| 5 | `rust-version.workspace = true` in the five members and `rust-version = "1.92"` in the desktop package. CI already builds with exactly 1.92.0. | `cargo metadata` reports 1.92 for all six packages |
| 6 | `# Errors` on `read_frame`, `storage::private_dir` and `access::resolve`. The CLI's `[PORTS]` stays as written, because that comment is the command's `--help` text, and the rustdoc lint is allowed on that one item. `missing_errors_doc` is not turned on: about 30 other functions would need docs first. | `cargo doc --workspace --no-deps` without warnings |
