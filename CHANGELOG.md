# Changelog

All notable changes in this repository are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Baseline for comparison:** upstream
[`cloudflare/odoh-client-rs`](https://github.com/cloudflare/odoh-client-rs)
`master` at `1dc3422` (2024-09-19), README of 19 lines, `odoh-rs =
"=1.0.0-alpha.1"`. This branch (`rfc9230-update`) updates the client to the
final RFC 9230 protocol.

---

## [Unreleased]

Changes on `rfc9230-update` relative to upstream `master`. Not yet proposed
upstream.

### Added

- `CHANGELOG.md` — this file: full change history, dependency list, README
  comparison, and verification results.
- Unit tests for the response validation (`validate_response` in
  `src/main.rs`): 2xx/`Content-Type` acceptance, and non-2xx, missing, and
  wrong `Content-Type` rejection.

### Changed

- **`odoh-rs` updated** `=1.0.0-alpha.1` → `1.0.5`.
  The alpha implemented ODoH version `0x0001` but pinned HPKE 0.5.1
  (draft HPKE); 1.0.5 uses HPKE 0.14.1 (RFC 9180).
- **`rand`** `0.8` (`std_rng`) → `0.10` (`std_rng`, `thread_rng`,
  `default-features = false`); `StdRng::from_entropy()` → `rand::rng()`.
- **`trust-dns-client` / `trust-dns-proto`** `0.20.1` → `0.23.2`.
- **`Cargo.lock`** regenerated: `odoh-rs` 1.0.5, `hpke` 0.14.1, `rand`
  0.10.3 (0.8.8 remains as a transitive dependency), `trust-dns-*` 0.23.2,
  plus transitive updates.
- **Default ODoH relay changed** from `https://odoh1.surfdomeinen.nl/proxy` to
  `https://odoh-relay.edgecompute.app`.
  - Files touched: `tests/config.toml` (default config used by the CLI and by
    the integration test) and `README.md` (configuration example).
  - Reason: the old host no longer resolves. Verified 2026-11-14 — DNS returns
    `::17` / `0.0.0.17` and the connection fails, so every query through the
    old default config failed.
  - The new relay is a public ODoH relay. Its DNSCrypt `sdns://` record encodes
    `odoh-relay.edgecompute.app` with path `/`, which matches how the client
    sends the POST (to the proxy URL as configured).
  - **Code impact:** no `.rs` file hardcoded the old relay. `src/main.rs` posts
    to whatever `proxy` value the TOML sets, so this is a configuration-only
    change.
- **`README.md` rewritten** to describe the actual code. See
  [README changes](#readme-changes) below.

### Fixed

RFC 9230 compliance gaps in the HTTP client (each verified against the RFC
text):

- **§4.3 — response `Content-Type`**: the client now rejects any response
  without `Content-Type: application/oblivious-dns-message` before processing
  the payload. Previously it processed the body whenever the status was 200.
- **§4.3 — redirects**: the reqwest client is now built with
  `redirect::Policy::none()`. Previously it used reqwest's default
  (`Policy::limited(10)`), which followed redirects directly and could bypass
  the proxy.
- **§4.1 — scheme**: the client now rejects `proxy`/`target` URLs that do not
  use `https`. Previously any scheme (including `http`) was accepted.
- **§4.3 — status**: the client now accepts any 2xx status, as the RFC
  specifies, instead of requiring exactly 200.
- **§4.5 — private state**: the `cookies` feature was removed from the
  `reqwest` dependency, so the client cannot store or send cookies.
- `src/main.rs:123` — removed a redundant `.clone()` on `Option<[u8; 16]>`
  (clippy `clone_on_copy`). This fixes `cargo clippy -- -D warnings`, which is
  a CI step in `.github/workflows/rust.yml`.
- **Target URI and config discovery**: the Target URI is now used exactly as
  configured, including its path (e.g. `https://doh.tiar.app/odoh`), and the
  `targetpath` sent to the proxy is the target's path; previously the client
  overwrote the path with `/dns-query`. The configuration is fetched from the
  well-known URI on the target **host**
  (`https://{host}/.well-known/odohconfigs`) instead of
  `{target}/.well-known/...`, which failed for targets whose URI has a path.

---

## Dependencies (current, 2026-11-14)

Direct dependencies from `Cargo.toml`, with versions locked in `Cargo.lock`:

| Crate | Requirement | Locked | Use |
| --- | --- | --- | --- |
| `odoh-rs` | `1.0.5` | `1.0.5` | ODoH / HPKE protocol operations |
| `rand` | `0.10` | `0.10.3` | RNG for HPKE and DNS query IDs |
| `reqwest` | `0.11` | `0.11.27` | HTTP client |
| `tokio` | `1` | `1.54.1` | Async runtime |
| `clap` | `2.33` | `2.34.0` | CLI argument parsing |
| `anyhow` | `1` | `1.0.104` | Error handling |
| `serde` | `1.0` | `1.0.229` | Config deserialization (derive) |
| `toml` | `0.5` | `0.5.11` | Config parsing |
| `trust-dns-client` | `0.23.2` | `0.23.2` | DNS query/record types |
| `trust-dns-proto` | `0.23.2` | `0.23.2` | DNS message wire format |
| `url` | `2.2` | `2.5.8` | URL parsing |
| `regex` | `1` | `1.13.1` | `TYPExxx` record-type parsing |
| `lazy_static` | `1.4` | `1.5.1` | Compiled regex for `TYPExxx` |
| `futures` | `0.3` | `0.3.34` | Declared, not used in `src/` |
| `hex` | `0.4` | `0.4.3` | Declared, not used in `src/` |
| `assert_cmd` (dev) | `1` | `1.0.8` | Integration test |

Transitive versions worth noting: `hpke` 0.14.1, `rand` 0.8.8 (transitive),
`rand_core` 0.6.4 / 0.10.1.

---

## README changes

### Versus upstream (`1dc3422`, 19 lines)

- Upstream said the client accesses resolvers running the **ODoH protocol
  draft-06** and linked to `draft-pauly-dprive-oblivious-doh-06`. Now it
  states **RFC 9230**.
- Upstream did not pin the `odoh-rs` version; now `1.0.5` is pinned and
  reflected in `Cargo.lock`.
- Upstream had only an example command. The README now also documents
  requirements, build, configuration (including the relay), usage, what a run
  does, testing, dependencies, files, license, and the changelog.
- Kept from upstream: the crates.io badge, the target resolver
  `https://odoh.cloudflare-dns.com`, the well-known `GET` config fetch, and the
  example command.

### Removed from the previous README (156 lines)

- **“Notes about `odoh-rs`”** — pointed to `benches/odoh_bench.rs`,
  `tests/test-vectors.json`, `examples/cli.rs`, and `fuzz/`. None of those
  files exist in this repository; they belong to the separate `odoh-rs`
  project. This was the main “not our code” content.
- **“`odoh-client-go`”** — described a different repository; not part of this
  code.
- **curl replay with `request.bin` and httpbin header-leak checks** — the
  client never writes a `request.bin` file, so the instructions could not be
  followed as written.
- **“Proxy testing workflow”** — replaced by an accurate **Testing** section
  (`cargo test`, manual run, shell loop).

### Added in the rewrite

- Protocol status table (version `0x0001`, ciphersuite, `odoh-rs` version).
- Requirements and build instructions.
- Configuration section with the new relay and an explanation of `target` /
  `proxy`.
- Usage synopsis plus the `TYPExxx` record-type note.
- “What a run does” — the actual request/response flow in `src/main.rs`.
- Dependency table, file list, license, and changelog link.

---

## Verification (2026-11-14)

- `cargo build` — OK (rustc 1.90.0, toolchain
  `stable-x86_64-pc-windows-gnu`).
- `cargo fmt -- --check` — OK.
- `cargo clippy -- -D warnings` — OK (after the one-line `clone_on_copy` fix
  above).
- `cargo test` — **OK**: 4 unit tests (response validation) + 1 integration
  test (real query through the configured proxy/target).
- **End-to-end query with the default config**:

  ```bash
  cargo run --quiet -- google.com A
  ```

  Result (exit 0):

  ```text
  Response: [Record { name_labels: Name("google.com."), rr_type: A, dns_class: IN, ttl: 263, rdata: Some(A(A(142.250.176.78))) }]
  ```

  Full path: `GET /.well-known/odohconfigs` → HPKE encrypt → `POST` to
  `odoh-relay.edgecompute.app` → relay forwards to
  `odoh.cloudflare-dns.com` → response `Content-Type` validated → decrypt →
  print answers.
- **Negative tests** (RFC 9230 §4.1):
  - `proxy = "http://odoh-relay.edgecompute.app"` →
    `Error: proxy URL must use https` (exit 1).
  - `target = "http://odoh.cloudflare-dns.com"` →
    `Error: target URL must use https` (exit 1).

---

## Notes

- `futures` and `hex` are declared in `Cargo.toml` but are not used anywhere
  in `src/`. They are left in place to keep the diff minimal.
- The integration test (`tests/integration_test.rs`) requires network access to
  the configured target and relay.
- The client uses the default ODoH ciphersuite only; `odoh-rs` does not provide
  full crypto agility.
- The client does not implement arbitrary RFC 6570 Proxy URI Templates from
  §4.1; it always sends the query-parameter form
  (`?targethost=...&targetpath=...`) to the configured proxy URL, which is one
  of the two template forms shown in the RFC examples.
