# How the demo is built

The demo is a .NET 8 solution, `HpspDemo.sln`, with four projects:

```
demo/
├── src/
│   ├── Hpsp.Core/              the protocol: no user interface, runs on any OS
│   ├── Hpsp.Demo.Ui/           shared Windows Forms pieces (activity window, checklist…)
│   ├── HpspAcuSimulator/       the ACU program     → HpspAcuSimulator.exe
│   └── HpspReaderSimulator/    the reader program  → HpspReaderSimulator.exe
├── tests/Hpsp.Core.Tests/      headless tests (dotnet run): spec examples, vectors, end to end
└── build/                      scripts that make the single-file .exe files
```

The two programs are thin: every protocol decision is made in `Hpsp.Core`, which the tests drive directly. You can read the protocol without reading any user-interface code.

## `Hpsp.Core`, folder by folder

| Folder | Files | What they do | Spec |
|---|---|---|---|
| `Cbor/` | `HpspCbor.cs`, `JsonNotation.cs` | Deterministic CBOR encoding. Strict decoding with the HPSP profile limits. The JSON notation used in the specification and in the activity window. | 4.3–4.5 |
| `Protocol/` | `HpspMessage.cs`, `Framing.cs` | The message envelope (`type`, `op`, `id`, `re`, `seq`, `mono`, `ts`, `data`) and the 4-byte length-prefixed frame. | 4.2, 4.6 |
| `Transport/` | `SessionTls.cs`, `TlsEngine.cs` | TLS 1.3 sessions with .NET's `SslStream` (SChannel on Windows). The engine switch, the Windows 10 check and platform detection. | 5.7 |
| `BouncyCastle/` | `Spake2Plus.cs`, `PairingTls.cs`, `SessionTlsBouncyCastle.cs` | **All BouncyCastle code, between banner comments.** SPAKE2+ (RFC 9383), TLS 1.3 with an external pre-shared key for pairing, and the alternative session engine. | 5.6, Annex E |
| `Security/` | `Grants.cs`, `DemoPki.cs` | The 84-byte grant layout, signing and every reader-side grant check. The demo certificate authority and certificate checks. | 5.4–5.5, 7 |
| `Cards/` | `Wiegand26.cs` | 26-bit H10301: parity, facility code, card number. | — |
| `Engine/` | `ReaderEngine*.cs`, `AcuEngine*.cs`, … | The two state machines. The reader: pairing, session, events, unlock. The ACU: site, pairing, sessions, access decisions, attack demos. Also the activity log entries and the message channel (framing plus fragmentation). | 5–8 |
| `Localization/` | `L.cs`, `French.cs`, `FrenchUi.cs` | English and French text. Protocol content is never translated. | — |

## The flow, and where to read it

1. **Create a site.** `AcuEngine.CreateSite` calls `DemoPki.CreateRoot`, then `IssueAcuCertificate` (serverAuth plus the names readers dial) and `IssueGrantSigner` (grant-signing usage only).
2. **Factory identity.** `ReaderEngine.CreateFactoryIdentity`: a manufacturer CA, an IDevID with a `urn:uuid` name, an 8-character setup code, and the SPAKE2+ verifier (`w0`, `L`) made from it.
3. **Pairing.**
   - `ReaderEngine.OpenPairingWindow` opens the window, and `PairOneAsync` handles an attempt.
   - `AcuEngine.AddReaderAsync` runs the other side: `pake_params` → `pake_share` ×2 → `pake_confirm`.
   - Both then derive the PSK and switch to `PairingTls`.
   - Inside it: `attest_request` (signed with the TLS exporter), `enroll` (the reader makes a new key and a CSR) and `cert_install`.
4. **Session.**
   - `ReaderEngine.SessionLoopAsync` → `TlsEngine.ConnectAsync`, then `hello` with a fresh session value.
   - `AcuEngine.HandleReaderAsync` checks the certificate and the `hello`, replies, and sends `trust_update` if needed.
   - Heartbeats every few seconds; three missed ends the session.
5. **A card.**
   - `ReaderEngine.SwipeCard` creates a `credential` event.
   - The ACU acknowledges it, checks its age, and looks it up in `AccessList`.
   - Allowed: `SignGrant`, then `SendUnlockAsync`, plus a green LED. Refused: a red LED and no grant.
6. **The unlock.** `ReaderEngine.OnUnlockAsync` → `GrantVerifier.Check` (signer, counter and floor, expiry, signature). The counter block is saved first, then the door opens for the requested time.

## Threads

- **Engine side.** Each engine runs its network work on background tasks and raises `Activity` and `StateChanged` events. The windows marshal these onto the UI thread (`BeginInvoke`). A 200–300 ms timer refreshes countdowns and the checklist.
- **BouncyCastle.** It is used in *non-blocking* mode for sessions (see the comment on `OwningStream`), because a session reads and writes at the same time.

## Building

- Windows: `dotnet build`, `dotnet run --project src\HpspAcuSimulator`, `dotnet run --project tests\Hpsp.Core.Tests`.
- The release `.exe` files are made by `build/publish.ps1` or `build/publish.sh`: self-contained, single-file, for `win-x64` and `win-arm64`.
- The projects also build on Linux and macOS, because the Windows Forms reference pack comes from NuGet there (see the `.csproj` files). The tests run there too.
