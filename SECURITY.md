# Security

## This is a demo

The Windows programs in `demo/` and the C reference in `c-reference/` exist to show how HPSP works and to check the specification. They are **not products** and **must never control a real door**. The demo takes shortcuts on purpose:

| Shortcut | Why | What a real system does |
|---|---|---|
| Keys are kept in plain files under `%LOCALAPPDATA%\HPSP Demo\` | So the demo is simple to inspect and reset | Device keys in a secure element or TPM; the grant-signing key in an HSM, separate from the ACU; the site root offline |
| **Show secrets** displays private keys, SPAKE2+ values and the pre-shared key | To learn how the protocol works | Never shown |
| The ACU signs grants itself | One program instead of two | The grant signer is a separate, hardened service |
| "Accept readers from any manufacturer" is on by default | Every simulated reader makes its own manufacturer CA | The ACU trusts only a configured list of manufacturer roots |
| The setup code is shown on screen | It stands for the label on the device | Printed on the device and its packaging |
| The C reference runs over plain TCP with the published Annex E test key | It tests the protocol core, not TLS | TLS 1.3 as specified, with real keys |

The programs are not code-signed, so Windows SmartScreen warns about them. Build them from source if you prefer (see [RUNNING.md](RUNNING.md)).

## What the demo does enforce

The protocol checks themselves are real, and the automated tests exercise them:

- **TLS 1.3 only.** Both sides present certificates. Each is checked against the site's own root only (never the Windows certificate store), for the right purpose (server/client), and for the right device (the UUID in the certificate must match `hello`).
- **SPAKE2+ (RFC 9383)** for commissioning, verified against the RFC's test vector and the specification's Annex E vector. Every attempt is counted before anything that could test a guess is revealed. After 5 failures pairing locks for 5 minutes, doubling up to an hour. A paired reader ignores the pairing button.
- **Attestation is bound to the session.** The reader signs a challenge together with a TLS exporter value from that exact pairing connection.
- **Grants.** The reader accepts a grant only if every check below passes:
  - the signer is a trusted grant signer (its certificate carries the grant-signing usage and no TLS usage, and is not revoked);
  - the counter is new and at or above the stored floor; the floor is saved before acting;
  - the grant has not expired (5-second clock allowance);
  - the signature covers this device, this session value, the action, the output and the duration.
- **Stale card reads never open a door.** A read older than 5 seconds, from before a reader restart, or delivered twice is logged and ignored.
- **Input limits.** CBOR is decoded with a strict profile (depth, size, no tags or indefinite lengths, no duplicate keys), and frames and fragments are bounded. Timeouts apply to TLS handshakes, `hello` and pairing.

## Review

The C# core was reviewed for security before the first release. Every finding was fixed, and regression tests were added for each confirmed one. The main ones:

- an old card read replayed after a reader restart could open the door;
- the pairing lock-out could be avoided by disconnecting mid-attempt;
- a non-signer site certificate could be installed as a grant signer.

## Known limitations (see the specification's open items)

- `trust_update` is not itself signed in this version of the specification. The reader trusts it because it arrives over the mutually authenticated session.
- Certificate extension and usage OIDs are placeholders until a private enterprise number is allocated. The demo's grant-signing usage `1.3.6.1.4.1.32473.1.1` uses the documentation number reserved by RFC 5612.
- Revocation is distributed with `trust_update`, not through CRLs or OCSP.

## Reporting a problem

If you find a weakness **in the specification**, or a bug in the code that would matter to a real implementation, please open an issue on this repository, or contact Highpower Security Products LLC privately if you would rather not disclose it publicly at first.
