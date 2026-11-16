# HPSP specification

| Document | Status |
|---|---|
| [HPSP 0.6 implementation draft (PDF)](HPSP_v0.6_implementation_draft.pdf) · [Word](HPSP_v0.6_implementation_draft.docx) | **Current draft.** Adds post-quantum cryptography: hybrid ML-KEM key exchange (SecP256r1MLKEM768) required on controllers, version 3 grants with an algorithm number (ML-DSA and hybrid ECDSA + ML-DSA), an AES-256 option and a transitional CNSA 2.0 profile. See section 5.18 and "What changed from version 0.5". |
| [HPSP 0.5 implementation draft (PDF)](previous/HPSP_v0.5_implementation_draft.pdf) · [Word](previous/HPSP_v0.5_implementation_draft.docx) | Previous draft. The C reference implements 0.5. The demo implements 0.5 plus the 0.6 hybrid key exchange (grants are still algorithm 1, ECDSA P-256, which 0.6 keeps unchanged). |
| [HPSP 0.4 public review draft (Word)](previous/HPSP_v0.4_public_review_draft.docx) | Earlier draft, kept for reference. |
| [HPSP 0.4 overview](previous/HPSP_v0.4_overview_public.md) | A short public overview of 0.4. |

Test vectors: [`spec_vectors.json`](../c-reference/vectors/spec_vectors.json) (0.5, still valid in 0.6) and [`spec_vectors_pq.json`](../c-reference/vectors/spec_vectors_pq.json) (0.6 post-quantum grants, Annex E.3).

Open items and placeholders (for example the certificate extension OIDs) are listed in the 0.6 draft's Annex F.

Licence: CC BY 4.0, see [LICENSE.md](LICENSE.md).
