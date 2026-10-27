# hexabox-trust

Public trust channel for HexaBox artifacts (B9). Start with `TRUST.md`.

`verifiers/` holds the reference copies of the standalone verifiers, with their hashes in `SHA256SUMS` and `TRUST.md`. Run these reference copies against what you received. A bundle's own `verify_identity.py` is covered by that bundle's signed manifest; bundles resealed on or after 2026-10-27 ship a copy byte-identical to the reference copy (same hash), and a copy with a different hash is an earlier generation. Nothing here is secret; the value of this repository is that it is the *only* place the root fingerprint and the pins are published.
