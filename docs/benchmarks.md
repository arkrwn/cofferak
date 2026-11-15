# Benchmarks

Numbers you can reproduce with one command:

```bash
./scripts/bench.sh            # 20,000 requests by default
```

CI runs the same script on every build (`sdk-smoke` job, step
"Benchmark"), so current Linux and macOS runner numbers are always in
the job log.

## What is measured

1. **Crypto primitives** (`cofferak-core/examples/crypto_bench.rs`):
   AES-256-GCM-SIV encrypt/decrypt of 64 B, 1 KB and 16 KB values with
   path-bound associated data (the work behind every `set`/`get`), and the
   hybrid X25519 + ML-KEM-1024 recovery wrap/unwrap (used only by `init`,
   `rotate-dek` and `recover`).
2. **End-to-end reads** (`sdk/rust/cofferak-sdk/examples/bench.rs`): the
   Rust SDK calling `get` against a running daemon, over the Unix socket
   and over TLS 1.3 + mutual TLS, with 1 and 8 client threads. Measured
   two ways: each call on a fresh connection (the per-call `Client`
   methods), and every call of a thread on one session (protocol
   version 2, [ADR 0019](adr/0019-protocol-v2-sessions.md)). Each `get`
   runs token lookup, the ACL check, decryption and an audit-log append.

The daemon is `cofferakd/examples/dev-daemon.rs`, which runs the same
request path as `cofferakd` but skips host-key unsealing (a one-time
startup step). Reads never touch `vault.cofferak`, writes are fsync'd to
disk before they are acknowledged (ADR 0010), so write latency depends
mostly on your disk.

## Results: Apple M3 Pro (arm64), macOS, release build

| Operation | Throughput | Latency |
|---|---|---|
| Decrypt 64 B secret (AES-256-GCM-SIV) | 4,070,000 ops/s | 0.24 µs |
| Decrypt 1 KB | 1,058,000 ops/s | 0.94 µs |
| Decrypt 16 KB | 85,700 ops/s (≈1.4 GB/s) | 11.7 µs |
| Encrypt 64 B (includes fresh random nonce) | 456,000 ops/s | 2.2 µs |
| Encrypt 16 KB | 70,900 ops/s (≈1.16 GB/s) | 14.1 µs |
| Recovery wrap (X25519 + ML-KEM-1024 + HKDF-SHA-384) | 16,700 ops/s | 60 µs |
| Recovery unwrap | 21,200 ops/s | 47 µs |
| `get` over Unix socket, 1 client thread | 9,870 req/s | p50 84 µs, p99 217 µs |
| `get` over Unix socket, 8 client threads | 15,750 req/s | p50 480 µs, p99 948 µs |
| `get` over TLS 1.3 + mTLS, new ML-KEM-1024 handshake per request, 1 thread | 1,480 req/s | p50 532 µs, p99 1.8 ms |
| `get` over TLS 1.3 + mTLS, new handshake per request, 8 threads | 5,460 req/s | p50 1.36 ms, p99 3.5 ms |

Measured 2026-11-11 with `./scripts/bench.sh 20000` (one representative run, repeated runs on the same laptop varied by roughly ±15%, more for TLS tail latency).

## Results: GitHub Actions `ubuntu-latest` runner (AMD EPYC 9V74, x86-64), release build

From the CI run of this change (`sdk-smoke (ubuntu-latest)` job, step
"Benchmark"), shared cloud runners vary from run to run.

| Operation | Throughput | Latency |
|---|---|---|
| Decrypt 64 B secret (AES-256-GCM-SIV) | 3,860,000 ops/s | 0.26 µs |
| Decrypt 1 KB | 2,112,000 ops/s | 0.47 µs |
| Decrypt 16 KB | 260,000 ops/s (≈4.3 GB/s) | 3.9 µs |
| Encrypt 64 B (includes fresh random nonce) | 1,420,000 ops/s | 0.70 µs |
| Encrypt 16 KB | 188,000 ops/s (≈3.1 GB/s) | 5.3 µs |
| Recovery wrap (X25519 + ML-KEM-1024 + HKDF-SHA-384) | 10,400 ops/s | 96 µs |
| Recovery unwrap | 12,100 ops/s | 83 µs |
| `get` over Unix socket, 1 client thread | 11,900 req/s | p50 82 µs, p99 143 µs |
| `get` over Unix socket, 8 client threads | 26,900 req/s | p50 258 µs, p99 828 µs |
| `get` over TLS 1.3 + mTLS, new ML-KEM-1024 handshake per request, 1 thread | 2,470 req/s | p50 402 µs, p99 469 µs |
| `get` over TLS 1.3 + mTLS, new handshake per request, 8 threads | 5,680 req/s | p50 1.35 ms, p99 2.57 ms |

## Sessions against a fresh connection per request

Same machine, same run, same daemon: an Intel Xeon 2.10 GHz cloud VM
(x86-64, Linux), release build, `./scripts/bench.sh 20000`, measured
2026-11-15. The absolute numbers of a shared VM are modest, the ratio is
the point.

| `get`, Rust SDK | Fresh connection per request | One session per thread | Gain |
|---|---|---|---|
| Unix socket, 1 thread | 5,490 req/s, p50 168 µs | 19,400 req/s, p50 46 µs | 3.5× |
| Unix socket, 8 threads | 4,570 req/s, p50 1.62 ms | 48,300 req/s, p50 130 µs | 10.6× |
| TLS 1.3 + mTLS, 1 thread | 1,180 req/s, p50 817 µs | 16,100 req/s, p50 57 µs | 13.7× |
| TLS 1.3 + mTLS, 8 threads | 2,770 req/s, p50 2.22 ms | 45,100 req/s, p50 134 µs | 16.3× |

With a session, a read over post-quantum mutual TLS costs about the same
as a read over the local Unix socket, because the handshake is paid once.
`get_many` goes further for a service that loads its configuration at
startup: any number of values up to 256 in one round trip.

## Reading the numbers

- **The crypto is not the bottleneck.** Decrypting a typical secret takes
  a quarter of a microsecond, an end-to-end local read takes about
  0.08 ms, dominated by opening a socket and appending to the audit log.
- **Post-quantum security costs microseconds, once.** The ML-KEM-1024
  recovery wrap runs only during `init`, `rotate-dek` and `recover`, it
  is never on the request path.
- **The per-request TLS numbers include a full handshake each time**
  (ML-KEM-1024 key exchange plus mutual certificate verification),
  because the per-call `Client` methods open a new connection for each
  call. They are an upper bound on cost. Even so, a remote read completes
  in about half a millisecond on localhost. A session pays the handshake
  once, see the table above.
- **Concurrency:** the daemon serialises requests through one lock, so
  adding client threads raises throughput but also per-request latency.
  For a secrets store, where services read a handful of values at
  startup, single-digit-millisecond tail latency at thousands of
  requests per second leaves ample headroom.
- Before ADR 0011, AES-256-GCM-SIV ran without hardware acceleration on
  arm64 (about 180 MB/s on the same machine). Moving it to AWS-LC made
  small-value decryption about 12× faster and large values about 8×.
