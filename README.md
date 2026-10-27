# hexabox-trust

Public trust channel for HexaBox artifacts (B9). Start with `TRUST.md`.

`verifiers/` holds the reference copies of the standalone verifiers, with their hashes in `SHA256SUMS` and `TRUST.md`. Run these reference copies against what you received; a bundle's own `verify_identity.py` is a later generation covered by that bundle's signed manifest and has a different hash. Nothing here is secret; the value of this repository is that it is the *only* place the root fingerprint and the pins are published.
