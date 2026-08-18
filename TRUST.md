# HexaBox trust channel — TRUST.md

This repository is the public trust anchor for HexaBox artifacts (blocker B9). Obtain the values below from **here**, the artifact from anywhere, and verify offline. Nothing in an artifact can substitute for the values on this page.

## Root

| | |
|---|---|
| Root public key (base64) | `DFSZPG2vtCa+t7f8oJFtw9WLzzfu1omTgDYDxWZB0fU=` |
| **Root fingerprint** (sha256 of the base64 text as shipped in `root.pub`) | `b5569d76d434123dc2f42c9dc54c13fdde0540c0143d2c68bdb6e877372405d6` |
| Ceremony | see `ceremony_record.json` (date, witnesses, custody) |

Verify any HexaBox agent bundle against this root:

    python3 verify_identity.py <bundle_dir> --trusted-root b5569d76d434123dc2f42c9dc54c13fdde0540c0143d2c68bdb6e877372405d6

(`verify_identity.py` ships in every bundle; a reference copy is published here once the first bundle generated under the anchored root exists — until then compare it against the copy inside a bundle you obtained through a second channel.)

## Release unreleased — pins

| Pin | Value |
|---|---|
| Fleet manifest signer (`verify_fleet_manifest.py --trusted-pubkey`) | `not yet published` |
| Delivery manifest signer (`verify_delivery_standalone.py --trusted-pubkey`) | `not yet published` |

## Verifiers (byte-identical copies; compare sha256 before running any in-package tool)

| File | sha256 |
|---|---|
| `verifiers/verify_delivery_standalone.py` | `da2b3ca436bf05110dc7128d1d59e70f7b8e412be6f91dccd19a3478bc63830c` |
| `verifiers/ed25519_verify.py` | `16b12bc2b0c984a928e34f4dbeff02746eae5af838035aaa95536c325c984b5a` |
| `verifiers/verify_fleet_manifest.py` | `5fedb32c07083496e4ecb00789747e3e14c20a211dd5b27e85117b943d6332a9` |
| `verifiers/delivery_manifest.py` | `52027c06400cfbb0e4656fd400b80e82eedacae54a6fcec07d8639db9f2546fa` |
| `verifiers/fleet_manifest.py` | `a48dab4803fd0173f3f7952f14d5e9e9c5a97625e8bf74cc7d0d88e95a32a181` |
| `verifiers/test_outer_verifiers.py` | `b32ff6006ea1f1afe270bbc8d4a16041af297f1cf574e46ebdd0606538ec64c0` |
| `ceremony_record.json` | `81695ad4db7e4a161f8c70eae2567c8761cad7cb524920a6afb9aba983514196` |
| `revocations.json` | `199f24efc0e284ace0e52a0be7da78c586993c4a3aa5362687b718e0ca2dd628` |

## Revocations

`revocations.json` — root-signed entries naming revoked generator keys. A bundle signed by a revoked generator still verifies offline (the mathematics do not change); this file is what tells you not to trust it. Check it when you are online.

## Rotation

A new root is announced here with a cross-signature from the old root and both fingerprints listed for the transition period. Reference (demo) keys used for CI and the Proving Ground are never listed here.

Ceremony record: `ceremony_record.json` (sha256 `81695ad4db7e4a161f8c70eae2567c8761cad7cb524920a6afb9aba983514196`).

*Published 2026-08-18. Status classes: values here are DELIVERED AND SIGNED once a release is tagged; before that, POST-DELIVERY, UNSIGNED.*
