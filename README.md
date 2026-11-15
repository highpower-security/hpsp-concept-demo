# HPSP concept demo

**HPSP (High Performance Security Protocol)** is a protocol for connecting access-control readers and door hardware to an access control unit (ACU) over a network. It is designed so that **a door opens only for a signed, single-use grant**, made for that device and that session, and so that installing a device is simple and safe.

This repository holds:

- the specification;
- a portable C reference of the device side;
- a hands-on Windows demo of the whole flow: commissioning a reader, then opening (or not opening) a door for a 26-bit card.

> **This is a teaching and evaluation demo, not a product.** It shows its keys on request, keeps them in plain files, and accepts readers from any manufacturer. Never connect it to a real door. See [SECURITY.md](SECURITY.md).

## Try the demo

**→ [RUNNING.md](RUNNING.md)** explains which file to download, how to start the programs and the five-minute walkthrough. ([Version française : RUNNING.fr.md](RUNNING.fr.md))

In short: download the zip for your PC from **Releases**, for example `HPSP-Demo-0.5.0-build2-win-arm64.zip` (`win-x64` for Intel/AMD, `win-arm64` for Arm PCs and Windows on Apple-silicon Macs; a higher build number is newer). Run **`HpspAcuSimulator.exe`**, then **`HpspReaderSimulator.exe`**, and follow the **Provisioning checklist** panel in each window.

| Program | What you can do |
|---|---|
| `HpspAcuSimulator.exe` | Create a demo site (root, TLS and grant-signer keys), keep an access list of facility/card numbers, pair readers with their setup code or QR text, and watch every decision. It also has buttons for five attacks that the reader must refuse. |
| `HpspReaderSimulator.exe` | Show the reader's setup code and QR code, press its pairing button, swipe a 26-bit H10301 card, and watch the door strike and LED. You can also pull the network cable to see events kept and replayed. |

Both programs have:

- an **activity window** showing every message in both directions, as JSON and as the CBOR bytes on the wire;
- a **Show secrets (demo only)** switch;
- a choice of **TLS engine** (Windows' own TLS 1.3, or BouncyCastle, which also works on Windows 10);
- **English and French** text.

## What is in the repository

| Folder | Contents | Licence |
|---|---|---|
| [`spec/`](spec/) | The HPSP 0.5 implementation draft (PDF and Word) and the earlier 0.4 public review draft. | CC BY 4.0 |
| [`c-reference/`](c-reference/) | A portable, allocation-free C99 implementation of the device side of the protocol core, a controller simulator, and tools that reproduce the specification's test vectors. See its [README](c-reference/README.md). | Apache-2.0 |
| [`demo/AcuSimulator/`](demo/AcuSimulator/) | Complete source of the **ACU Simulator** (C#, .NET 8): its window, the protocol library `Hpsp.Core`, shared window pieces and the tests. Builds on its own. | Apache-2.0 |
| [`demo/ReaderSimulator/`](demo/ReaderSimulator/) | Complete source of the **Reader Simulator**, laid out the same way. The shared parts are identical copies. See [ARCHITECTURE.md](demo/ARCHITECTURE.md). | Apache-2.0 |

## The protocol in one page

1. **Commissioning (pairing).** A reader leaves the factory with an identity certificate and a **setup code** printed on its label. At the site, someone presses the reader's pairing button. This proves they are physically present, and it opens a 10-minute window. The ACU and the reader then run **SPAKE2+** with the setup code. Both prove they know it, yet the code never crosses the network, and a wrong guess is counted (5 wrong codes lock pairing). SPAKE2+ yields a shared key, which starts **TLS 1.3** with a pre-shared key. Inside that link:
   - the reader proves its factory identity, bound to this exact session (`attest_request`);
   - it makes a fresh key pair (`enroll`);
   - it receives a certificate from the site's own root (`cert_install`).
2. **Sessions.** The reader always dials the ACU, over **TLS 1.3 with certificates on both sides**, each checked against the site root. Its `hello` carries a fresh 32-byte **session value**.
3. **Events.** Card reads and door changes are numbered events. The reader keeps them until the ACU acknowledges them, and replays them after a reconnect. A card read that arrives too late, or one from before a restart, is logged but never opens a door.
4. **Grants.** To open a door the ACU asks a separate **grant signer**, ideally in a hardware security module, to sign a grant. The grant covers this device, this session value, a counter that always goes up, the action, the duration and a short expiry. The reader opens the door only if every check passes. So even someone who controls the network, or a stolen ACU without the grant signer, cannot open doors. In the demo, try the replay, expired, old-session, tampered and wrong-signer attacks.
5. **Encoding.** Messages are deterministic CBOR (RFC 8949) in a length-prefixed frame. The specification shows them as JSON for readability.

## Status

- Specification: **0.5 implementation draft**. Open items are listed in its annexes, and certificate extension OIDs are placeholders.
- C reference: 53 unit checks (plus 200,000 mutated messages) and 27 scenario checks against the controller simulator.
- Demo: 130 automated checks, including both TLS engines in every combination, all the specification's examples and test vectors, and the full commissioning-to-unlock flow. The code was reviewed for security; see [SECURITY.md](SECURITY.md).

## Licences

- Code (`c-reference/`, `demo/`): **Apache License 2.0**, see [LICENSE](LICENSE).
- Specification documents (`spec/`): **Creative Commons Attribution 4.0** (CC BY 4.0), see [spec/LICENSE.md](spec/LICENSE.md).
- Third-party components: see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

Copyright © 2026 Highpower Security Products LLC.
