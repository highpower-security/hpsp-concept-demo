# HPSP reference implementation (host build)

A portable, allocation-free C99 implementation of the **device side** of the
HPSP protocol core, written alongside the HPSP 0.5 implementation draft. It also
includes a controller simulator and tools that reproduce the test vectors in the
specification.

> **Test use only.** The device program talks to the simulator over **plain TCP
> on localhost**, and it uses the **published test signing key** from Annex E.
> It must never be connected to a real door. TLS is not implemented here (see
> "What is not included").

## What is included

| Part | Files | What it does |
|---|---|---|
| CBOR | `src/hpsp_cbor.[ch]` | Reader and writer for the HPSP CBOR profile: definite lengths, no tags, no null, text keys, depth ≤ 6, ≤ 24 members, no duplicate keys, valid UTF-8. |
| SHA-256 | `src/hpsp_sha256.[ch]` | FIPS 180-4. |
| Grant check | `src/hpsp_grant.[ch]` | The 84-byte grant layout v2 and the device's checks in the order the spec gives: signer, counter and boot floor, expiry, signature. ECDSA P-256 by [p256-m](https://github.com/mpg/p256-m) (Apache-2.0), vendored in `third_party/`. |
| Device core | `src/hpsp_device.[ch]` | Framing, fragments, the envelope, `hello`, heartbeats with `mono_now`, reliable events with acknowledgment and replay, `unlock` / `lock` / `get_caps` / `goodbye`, timed and latched unlocks, `link_loss_grace_s`. |
| Porting layer | `hpsp_port` in `src/hpsp_device.h` | Seven functions: send, close, monotonic time, random bytes, non-volatile write, drive an output, log. |
| POSIX test device | `posix/device_main.c` | Runs the core over TCP and simulates one card read. |
| Controller simulator | `tools/sim_controller.py` | Signs grants with the test key and runs 27 scenario checks against the device. |
| SPAKE2+ | `tools/spake2plus.py`, `tools/hpsp_pake_vector.py` | Reference SPAKE2+ (RFC 9383) that reproduces the RFC's own test vector, and generates the HPSP commissioning vector. Python, for vectors only, not constant time. |

## Running it

```sh
make test     # unit tests under AddressSanitizer and UBSan, incl. 200,000 mutated messages
make device   # build the POSIX test device
make sim      # run the controller simulator against it
make pake     # reproduce the RFC 9383 vector and the HPSP commissioning vector
make fuzz     # 3-minute libFuzzer run (needs clang with libFuzzer)
make size     # code size on the host
```

Requires a C99 compiler and Python 3 with `cbor2`, `cryptography` and `ecdsa`.

## What the tests check against the specification

The test data in `tests/spec_data.h` is **generated from the specification
itself** (`vectors/spec_examples.json` and `vectors/spec_vectors.json` are
exported from the document's source), so the code is checked against the
document, not against itself.

* The grant signing input built by the C code equals Annex E byte for byte, and
  the published signature verifies with p256-m.
* All 102 distinct example messages in the specification pass the CBOR profile.
* The specification's own `hello` response and `unlock` example, with its real
  grant, are fed to the device: the door is released, the replay is refused, and
  the strike re-secures after 5 seconds with a `lock_state` event.
* Over the network: replay, wrong session, expired grant, unknown signer, wrong
  action, short duration, fragments, oversized fragments, heartbeats, event
  replay after a connection fault, a session-1 grant refused in session 2, a
  latched unlock secured on session loss, and that every device message is
  deterministic CBOR within `max_msg`.
* A libFuzzer run of 3 minutes (about 25 million inputs, seeded with the spec's
  examples) found no crash, leak or undefined behavior.
* The SPAKE2+ code reproduces RFC 9383's test vector exactly, then the HPSP
  commissioning vector in Annex E.

## Measured size (Cortex-M4, clang -Os, Thumb-2)

| Module | Code (bytes) |
|---|---|
| CBOR | 2,340 |
| SHA-256 | 1,038 |
| Grant check | 579 |
| Device core | 9,284 |
| p256-m (ECDSA, ECDH, key generation) | 4,242 |
| **Total** | **17,483** |

RAM: the `hpsp_device` structure is about 14 KB (7.5 KB event buffer for 32
events, 4 KB fragment buffer, 1 KB receive buffer). The deepest stack frame is
about 1.1 KB. TLS, the IP stack and the application are not included.

## What is not included

* **TLS 1.3.** The port's `send` and the bytes passed to `hpsp_device_on_bytes`
  are the plaintext side of the TLS session. On a device, connect them to
  mbedTLS or wolfSSL configured as the specification's crypto profile describes.
* **Commissioning in C.** SPAKE2+ exists here only as a Python reference used to
  produce vectors. A device implementation needs a constant-time version.
* **Non-volatile storage of critical events.** The specification requires it;
  the host build keeps events in RAM only.
* **Other operations:** configuration, firmware update, trust updates,
  recovery, inputs, indicators, the OSDP gateway and the card relay.
* **Timing on a real processor.** Measure it on the target.

## License

To be decided by Highpower Security Products LLC (the specification suggests
Apache-2.0 for the reference implementation). `third_party/p256-m` is
Apache-2.0, © Manuel Pégourié-Gonnard; see its LICENSE file.
