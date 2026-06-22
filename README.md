# sml-tls-tool

IMPURE, quarantined conformance and fuzz harnesses for
[`sml-tls`](https://github.com/sjqtentacles/sml-tls). This is a TOOL,
not a pure library: it opens real TCP sockets, spawns subprocesses, and
reads from stdin (AFL). All TLS protocol logic stays in the pure
`lib/github.com/sjqtentacles/sml-tls/` core; this repo only owns byte
transport, the BoGo wire protocol, and fuzz harness plumbing.

This is Track A5 of the sml-tls hardening plan. The harnesses build
**now**; they execute successfully at the J2 gate (after J1 wires AEAD
record protection and the full handshake into the state machine). Until
then the differential / conformance runs are expected to fail.

## Layout

```
sml-tls-tool/
  README.md                  this file
  Makefile                   build every harness with MLton
  sml.pkg                    package manifest (depends on sml-tls)
  lib/github.com/sjqtentacles/   vendored sml-tls + crypto tower (no .git)
  src/
    socket_shim.sig/sml      TCP driver: drives TlsClient/TlsServer over real sockets
    bogo_shim.sig/sml        BoringSSL BoGo runner shim
  cli/
    socket_shim.mlb          MLB for the socket driver CLI
    socket_main.sml          CLI entry: `socket_shim client HOST PORT | server PORT`
    bogo_shim.mlb            MLB for the BoGo shim CLI
    bogo_main.sml            CLI entry: invokes BogoShim.main ()
  scripts/
    run_bogo.sh              fetch BoGo, build runner, run a starter subset
    run_tlsfuzzer.sh         run a tlsfuzzer scenario against our server
    tlsfuzzer_1rtt.py        starter 1-RTT tlsfuzzer scenario
    run_openssl_diff.sh      OpenSSL differential (both directions)
    run_afl.sh               run AFL++ against all decoders in parallel
    generate_corpus.py       regenerate fuzz/corpus/ seed files from RFC 8448
  fuzz/
    afl_harness.sml          shared persistent-mode loop
    afl_record.sml           TlsRecord.decodePlaintext
    afl_ciphertext.sml       TlsRecord.decodeCiphertext
    afl_clienthello.sml      TlsHandshake.decodeClientHello
    afl_serverhello.sml      TlsHandshake.decodeServerHello
    afl_certificate.sml      TlsHandshake.decodeCertificate
    afl_extensions.sml       TlsExtensions decoders (active after A3 lands)
    afl_recordprotect.sml    TlsRecordProtect.unprotect (active after A1 lands)
    corpus/                  seed corpora (RFC 8448 byte shapes)
```

## Prerequisites

- **MLton** (build all harnesses). `brew install mlton` on macOS.
- **Python 3.8+** for `generate_corpus.py` and tlsfuzzer.
- **OpenSSL CLI** (1.1.1+ or 3.x) for the differential harness.
- **AFL++** (`brew install afl-fuzz`) for fuzzing.
- **Go toolchain** + **cmake/ninja** to build BoringSSL's BoGo runner.
- **tlsfuzzer**: `pip install tlsfuzzer`.

## Build

```
make                          # build socket_shim + bogo_shim + all AFL harnesses
make bin/socket_shim          # just the TCP driver CLI
make bin/bogo_shim            # just the BoGo shim CLI
make afl-all                  # just the AFL harnesses
make corpus                   # regenerate fuzz/corpus/ from RFC 8448
make clean                    # remove bin/ and out/
```

All harnesses compile today against the Phase-0 stubs of `TlsRecordProtect`
and `TlsExtensions` (which `raise Fail "todo: A1"` / `"todo: A3"`); the
AFL harnesses will therefore crash on every input until those tracks
land, which is exactly what AFL should surface at J2.

## Running each harness

### 1. Socket shim (foundation for all differential testing)

```
./bin/socket_shim client 127.0.0.1 4433
./bin/socket_shim server 4433
```

Drives a single TLS 1.3 handshake through the pure `TlsClient` /
`TlsServer` state machine over a real TCP connection. The X25519 key
and randoms are deterministic zeros for now; this is the transport
foundation. It will fail at the AEAD boundary until J1.

### 2. BoringSSL BoGo

```
scripts/run_bogo.sh                     # default starter test
scripts/run_bogo.sh -test=TestBasic-Client
```

The script:
1. Builds `bin/bogo_shim`.
2. Clones BoringSSL to `vendor/boringssl/` if missing.
3. Builds the BoGo runner (`ssl/test/runner`).
4. Runs the runner against our shim on a loopback port.

The shim parses the BoGo CLI flag subset (`-server`/`-client`, `-port`,
`-min-version`/`-max-version`, `-expect-handshake-success`,
`-expect-.*-error`, `-expect-msg`) and delegates the handshake to
`SocketShim`. PORTING.md for the shim protocol:
<https://boringssl.googlesource.com/boringssl/+/master/ssl/test/PORTING.md>.

### 3. tlsfuzzer

```
scripts/run_tlsfuzzer.sh                                # default 1-RTT scenario
scripts/run_tlsfuzzer.sh scripts/tlsfuzzer_1rtt.py
```

The script launches `bin/socket_shim server PORT` in the background,
then runs a tlsfuzzer scenario (Python) against it. The starter
scenario asserts a 1-RTT TLS 1.3 handshake completes. Expand the
scenario suite as the library gains features.

### 4. OpenSSL differential

```
scripts/run_openssl_diff.sh                             # both directions
scripts/run_openssl_diff.sh client                      # our client vs openssl s_server
scripts/run_openssl_diff.sh server                      # our server vs openssl s_client
```

Captures both transcripts and reports divergences. The pure sml-tls
library is deterministic; any divergence from OpenSSL is a library
bug to capture as a regression at J2.

### 5. AFL fuzzing

```
scripts/run_afl.sh                  # fuzz all decoders in parallel
scripts/run_afl.sh record           # fuzz one decoder
```

Each decoder harness is persistent-mode (`AFL_PERSISTENT=1`) for
throughput. Seed corpora live under `fuzz/corpus/<decoder>/` and are
regenerated from RFC 8448 shapes by `scripts/generate_corpus.py`.
Decoders fuzzed:

| Harness                | Decoder                              | Status      |
|------------------------|--------------------------------------|-------------|
| `afl_record`           | `TlsRecord.decodePlaintext`          | active      |
| `afl_ciphertext`       | `TlsRecord.decodeCiphertext`         | active      |
| `afl_clienthello`      | `TlsHandshake.decodeClientHello`     | active      |
| `afl_serverhello`      | `TlsHandshake.decodeServerHello`     | active      |
| `afl_certificate`      | `TlsHandshake.decodeCertificate`     | active      |
| `afl_extensions`       | `TlsExtensions` decoders             | after A3    |
| `afl_recordprotect`    | `TlsRecordProtect.unprotect`         | after A1    |

At J2, each AFL-discovered crash is minimized and added to the corpus
as a regression fixture **before** the fix lands, in the relevant pure
test file under `sml-tls/test/`.

## Quarantine

This repo is **impure** and is NOT part of the dual-compiler
deterministic purity guarantee of `sml-tls`. There is no `make test`
target here. The protocol logic is tested in the pure core; this tool
exists only to drive the pure core against real-world TLS endpoints and
malicious inputs.

## License

Same as `sml-tls` (MIT).
