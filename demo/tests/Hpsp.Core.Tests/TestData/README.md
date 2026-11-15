# Test data

These files are exported from the HPSP specification's own source, so the tests check the code against the published document, not against itself.

| File | Contents |
|---|---|
| `spec_examples.json` | Every JSON example message in the specification. Each one is encoded to CBOR, decoded again and compared. |
| `spec_vectors.json` | The Annex E test vectors: the grant signing input and signature, and the SPAKE2+ commissioning vector. |

**About `privHex` in `spec_vectors.json`:** this is the **published test signing key** from Annex E of the specification. It is printed in the document so that anyone can reproduce the test signature. It is **not a secret** and **must never be trusted by a real device**. No other private key is stored in this repository: the demo programs create their own keys when they first run, and keep them on the user's computer.
