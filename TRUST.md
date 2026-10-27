# HexaBox trust channel — TRUST.md

This repository is the public trust anchor for HexaBox artifacts (blocker B9). Obtain the values below from **here**, the artifact from anywhere, and verify offline. Nothing in an artifact can substitute for the values on this page.

## Root

| | |
|---|---|
| Root public key (base64) | `DFSZPG2vtCa+t7f8oJFtw9WLzzfu1omTgDYDxWZB0fU=` |
| **Root fingerprint** (sha256 of the base64 text in `root.pub` with the trailing newline removed; the value `verify_identity.py --trusted-root` takes) | `b5569d76d434123dc2f42c9dc54c13fdde0540c0143d2c68bdb6e877372405d6` |
| Ceremony | see `ceremony_record.json` (date, witnesses, custody) |

Verify any HexaBox agent bundle against this root:

    python3 verify_identity.py <bundle_dir> --trusted-root b5569d76d434123dc2f42c9dc54c13fdde0540c0143d2c68bdb6e877372405d6

The independent check is to run the reference copy from this repository (`verifiers/verify_identity.py`, sha256 below) against the bundle. Every bundle also ships its own `verify_identity.py`, covered by the bundle's signed manifest. Bundles resealed on or after 2026-10-27 ship a copy that is byte-identical to the reference copy (same sha256 as below); a bundle copy with a different hash is an earlier generation — use the reference copy.

Verdicts: exit 0 prints one line beginning `genuine ✓`; exit 1 prints `FAILED ✗` (tampering, a broken root chain, a root that does not match `--trusted-root`, a symlink or compiled Python outside the signed runtime outputs, or a manifest path that is not a normalised relative path); exit 2 prints `NOT VERIFIABLE ✗` (an unsigned handoff build or a pending identity — nothing is attested).

## Pins

| Pin | Value |
|---|---|
| Fleet manifest signer (`verify_fleet_manifest.py --trusted-pubkey`) | `not yet published` |
| Delivery manifest signer (`verify_delivery_standalone.py --trusted-pubkey`) | `not yet published` |
| **Action attestation signer** (`verify_action_attestation.py --trusted-pubkey`; spec `ACTION_ATTESTATION.md`; one pin per fleet instance, labelled by `signer.id`) | instance `ds5777` (Eihwaz fleet, executor agent `92052e6a-b350-41c8-8c51-5ba50da5a1d7`) · signer_id `ae3aeb73b0c64f67` · pubkey `TvoNGiXYfJSD0GjhBodX/UwOWeYNyxhOIVnWN+wNSj0=` · pinned 2026-10-24 |

## Reference verifiers and files (sha256 of the files in this repository)

| File | sha256 |
|---|---|
| `verifiers/verify_delivery_standalone.py` | `da2b3ca436bf05110dc7128d1d59e70f7b8e412be6f91dccd19a3478bc63830c` |
| `verifiers/ed25519_verify.py` | `16b12bc2b0c984a928e34f4dbeff02746eae5af838035aaa95536c325c984b5a` |
| `verifiers/verify_fleet_manifest.py` | `2ae84c8faa704a46b2c92d0ba52fbd6c96fa4ba88d12dead1bc58dd6c50cdcd1` |
| `verifiers/delivery_manifest.py` | `52027c06400cfbb0e4656fd400b80e82eedacae54a6fcec07d8639db9f2546fa` |
| `verifiers/fleet_manifest.py` | `a48dab4803fd0173f3f7952f14d5e9e9c5a97625e8bf74cc7d0d88e95a32a181` |
| `verifiers/test_outer_verifiers.py` | `877bb41d1cbf82e4853383b2d104bd8eac6925fda971381d2381d56e702b8583` |
| `verifiers/verify_identity.py` | `639309667fe7598550dcc18161159f99fc32fa4104577eaee6f27f3f50fc9ace` |
| `verifiers/verify_action_attestation.py` | `4c12842e1574038e96d07b02ff277755f6f843502ace6daa4c93d274a3d045e1` |
| `ceremony_record.json` | `81695ad4db7e4a161f8c70eae2567c8761cad7cb524920a6afb9aba983514196` |
| `revocations.json` | `199f24efc0e284ace0e52a0be7da78c586993c4a3aa5362687b718e0ca2dd628` |
| `ACTION_ATTESTATION.md` | `96c364736dcd7bc1cded7cc8c67fd55c53debc9bb549ee60011b95c430ce3b5c` |

## Revocations

`revocations.json` — root-signed entries naming revoked generator keys. A bundle signed by a revoked generator still verifies offline (the mathematics do not change); this file is what tells you not to trust it. Check it when you are online.

## Rotation

A new root is announced here with a cross-signature from the old root and both fingerprints listed for the transition period. Reference (demo) keys used for CI and the Proving Ground are never listed here.

Ceremony record: `ceremony_record.json` (sha256 `81695ad4db7e4a161f8c70eae2567c8761cad7cb524920a6afb9aba983514196`).

*Published 2026-08-19. Status classes: values here are DELIVERED AND SIGNED once a release is tagged; before that, POST-DELIVERY, UNSIGNED.*
