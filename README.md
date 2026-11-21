# odoh-client-rs

[![Latest Version]][crates.io]

[Latest Version]: https://img.shields.io/crates/v/odoh-client-rs.svg
[crates.io]: https://crates.io/crates/odoh-client-rs

`odoh-client-rs` is a CLI Rust client for Oblivious DNS over HTTPS (ODoH) as
specified in **RFC 9230**. All protocol and HPKE (RFC 9180) operations are
delegated to the [`odoh-rs`](https://crates.io/crates/odoh-rs) crate (`1.0.5`).

It is mainly intended for testing: it sends one query per invocation and prints
the answer records.

## Protocol status

| Item | Value |
| --- | --- |
| ODoH protocol version | `0x0001` (RFC 9230) |
| Ciphersuite | KEM `X25519HkdfSha256`, KDF `HkdfSha256`, AEAD `AesGcm128` |
| `odoh-rs` dependency | `1.0.5` (locked in `Cargo.lock`) |

The client uses the default ciphersuite only; `odoh-rs` does not provide full
crypto agility.

## RFC 9230 compliance

The client enforces these requirements from the RFC:

- **§4.1**: `POST` with `Content-Type` and `Accept:
  application/oblivious-dns-message`, `targethost`/`targetpath` query
  parameters, `Cache-Control: no-cache, no-store`, and `https` for both the
  proxy and the target.
- **§4.3**: only 2xx responses are processed, and only when the response
  carries `Content-Type: application/oblivious-dns-message`.
- **§4.3**: redirects are not followed automatically (any follow-up would have
  to go through the proxy).
- **§4.5**: no cookies or other private state are sent.
- **§5**: configs with an unsupported version or HPKE suite are ignored.
- **§6.1/§7**: message type, key ID, and all-zero padding are validated by
  `odoh-rs`.
- **§9**: the mandatory ciphersuite (DHKEM(X25519, HKDF-SHA256),
  HKDF-SHA256, AES-128-GCM) is supported.

The response validation is covered by unit tests (`cargo test`).

## Requirements

- Rust stable (built and run with `1.90.0`, toolchain
  `stable-x86_64-pc-windows-gnu`).
- A C linker. On Windows, the GNU toolchain with
  [WinLibs](https://winlibs.com/) works and is lighter than installing Visual
  Studio:

```bash
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

On Linux/macOS the default toolchain is enough.

## Build

```bash
cargo build
```

## Configuration

The proxy and target are read from a TOML file passed with `-c`/`--config`. The
default path is `tests/config.toml`.

```toml
[server]
# Optional. If omitted, the query is sent directly to the target, which
# defeats the purpose of using ODoH.
proxy = "https://odoh-relay.edgecompute.app"
target = "https://odoh.cloudflare-dns.com/dns-query"
```

- `target` is the full Target URI, **including its path** (for example
  `https://odoh.cloudflare-dns.com/dns-query` or `https://doh.tiar.app/odoh`);
  the query is sent exactly to that URI.
- The target configuration is fetched from the well-known URI on the target
  **host**: `GET https://{host}/.well-known/odohconfigs`. (RFC 9230 leaves
  config discovery out of scope; this is the convention used by deployments.)
- `proxy` is the ODoH relay. The default is the public relay
  `https://odoh-relay.edgecompute.app`. The relay that was previously
  configured here is no longer available; see `CHANGELOG.md`.

## Usage

```bash
cargo run -- <domain> <type> [-c FILE]
```

Examples:

```bash
cargo run -- google.com A
cargo run -- example.com AAAA -c tests/config.toml
```

Arguments:

- `domain`: domain to query.
- `type`: DNS record type (`A`, `AAAA`, `TXT`, ...). Unknown types are
  accepted as `TYPExxx` (for example `TYPE45`).
- `-c`, `--config`: path to the TOML configuration file (default
  `tests/config.toml`).

## What a run does

1. Fetches the target configuration with
   `GET https://{target host}/.well-known/odohconfigs` and uses the first config.
2. Builds the DNS query and encrypts it with HPKE. The query is wrapped in an
   `ObliviousDoHMessagePlaintext` with 1 byte of padding; the protocol version
   `0x0001` is set by `odoh-rs`.
3. Sends a `POST` with `Content-Type`/`Accept:
   application/oblivious-dns-message` and `Cache-Control: no-cache, no-store`
   to the proxy, adding `?targethost=<target host>&targetpath=<target path>`.
   Without a proxy, the request goes directly to the target URI.
4. Validates the response status and `Content-Type`, decrypts it, and prints
   the answer records as `Response: [...]`.

## Testing

`cargo test` runs the unit tests (response validation) and the integration
test (the built binary against the configured proxy/target):

```bash
cargo test
```

Manual functional test:

```bash
cargo run -- google.com A
```

Repeated requests for timing (the client does not collect statistics itself):

```bash
for i in $(seq 1 20); do
  cargo run --quiet -- google.com A >/dev/null || echo "request $i failed"
done
```

## Dependencies

Direct dependencies from `Cargo.toml`, with the versions locked in
`Cargo.lock`:

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

## Files

- `src/main.rs` — CLI, client session, request/response flow.
- `src/config.rs` — TOML configuration (`[server]` with `proxy`/`target`).
- `src/dns_utils.rs` — DNS query creation and answer printing.
- `tests/config.toml` — default proxy/target configuration.
- `tests/integration_test.rs` — runs the binary against the default config.
- `CHANGELOG.md` — detailed change history.
- `LICENSE` — BSD-2-Clause.

## License

BSD-2-Clause. See `LICENSE`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).
