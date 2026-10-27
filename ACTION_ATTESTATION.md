# HexaID Action Attestation — `hexabox.action_attestation/v1`

**Status:** v1, normative. **Published:** 2026-10-24. **Verifier:** `verifiers/verify_action_attestation.py` (sha256 in `SHA256SUMS`). **Signer pin:** `TRUST.md` → *Action attestation signer*.

## 1. What this is

When a HexaBox-governed agent performs a response action in an external system — isolating a host, stopping a process tree, quarantining files, blocking an indicator — the call carries one extra HTTP header:

```
X-HexaID-Attestation: <payload>.<signature>
```

The header is a compact, Ed25519-signed statement that **this exact action**, against **this exact target**, was executed by **a named, signed HexaBox agent**, after **N independent human approvals** recorded by the customer's command authority (each with the MFA basis the authority recorded), under a stated **security posture**, for **this receiver** (audience) and **this single dispatch** (idempotency key), valid for five minutes.

A receiver that does not know the header ignores it. Nothing is required of the receiver. A receiver that wants to know whether an incoming action is genuinely sanctioned verifies the header **offline**, with the standalone verifier or any Ed25519 library, against the signer public key published **here** — never against anything inside the token.

## 2. What it proves — and what it does not

| Proves | Does not prove |
|---|---|
| Which governed agent executed the action (`executor`: HexaID `agent_id`, `generator_id`, `root_id`, `provenance_hash`, doctrine version). The agent's own signed identity is verifiable separately with `verify_identity.py` against the root fingerprint on `TRUST.md`. | That the agent's *deployment* is the one you contracted — bind `executor.agent_id` to your own record of the agent you admitted. |
| That exactly this command (`command.digest` over the full immutable command) was **approved** by the customer's command authority at `approval.revision`, by `approval.approvers` (count and roles; principals hashed). | Who the approvers are by name — deliberately. The hash lets the operator resolve a dispute from their own ledger; it never carries a name or e-mail. |
| The posture the fleet was in when it dispatched. | The customer's consent to **your** terms of service — that remains your own credential (the bearer token on the same call). |
| That the token was minted for **you** (`audience` = your API host) and **this** call (`idempotency_key` = the `Idempotency-Key` header on the same request). | Anything about calls that do not carry the header. Absence means *not attested*, not *forbidden*. |

## 3. Three governance layers, one statement

The token binds the layers that already exist inside a HexaBox fleet:

1. **Standing identity.** The executing agent ships a root-chained, Ed25519-signed `identity.json` (schema `hexabox.identity/v1`). The runtime verifies that chain before it states `executor.identity_signed: true`. → `executor`. Capability leases that scope fleet members are a separate, internal layer and are not stated in this token.
2. **Per-action sanction — approvals.** Every privileged action has a content-bound reference (hash over action, target, parameters, tenant, tier). An approval is a record pinned to that reference, made by an authenticated, role-holding approver whose MFA the authority records together with its basis (`mfa_basis`, for example `edge_session` when an authenticated operator console asserts the person, or `idp_claim` when the identity provider does; `edge_session` is not a second factor). The fleet counts approvers after normalising their names (Unicode NFKC, trimmed, whitespace collapsed, case-folded) and dispatches only when the number of distinct approvers reaches the strictest of the authority's stated requirement, the fleet's own floor (`FLEET_ACTION_APPROVAL_MIN`) and its tier floor: tier 4, or a tier the fleet cannot determine, always requires two. → `mandate`, `approval`.
3. **The command itself.** An immutable logical command (`command_id`, `event_id`, `customer_id`, `action`, `provider_action`, `target`, `parameters`, validity window) with a SHA-256 digest; the durable lifecycle guarantees a single dispatch under one idempotency key. → `command`, `idempotency_key`.

## 4. Wire format

```
X-HexaID-Attestation: <base64url(payload_bytes)>.<base64url(signature)>
```

* `payload_bytes` — the UTF-8 bytes of the JSON payload, **compact, keys sorted at every level** (`json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`). The signature is computed over **exactly these bytes**; a verifier never re-serialises — it decodes and verifies the bytes it received.
* `signature` — 64-byte Ed25519 (RFC 8032) signature over `payload_bytes` with the attestation signer's private key.
* base64url without padding (RFC 4648 §5). Both parts non-empty; exactly one `.`.

## 5. Payload

```json
{
  "schema": "hexabox.action_attestation/v1",
  "alg": "ed25519",
  "attestation_id": "<32 hex, unique per token>",
  "issued_at": "2026-10-24T09:12:03Z",
  "expires_at": "2026-10-24T09:17:03Z",
  "audience": "eu2-cloud.acronis.com",
  "idempotency_key": "<64 hex — equals the Idempotency-Key header on the same request>",
  "executor": {
    "agent_id": "<HexaID agent uuid>", "generator_id": "<16 hex>", "root_id": "<16 hex>",
    "provenance_hash": "<64 hex>", "doctrine_version": "ruleset-14i-1.0.0",
    "identity_signed": true, "identity_root_anchored": true
  },
  "signer": { "id": "<16 hex = sha256(pubkey)[:16]>", "pubkey_b64": "<32-byte Ed25519 public key, base64>" },
  "command": {
    "command_id": "…", "event_id": "…", "customer_id": "…",
    "action": "isolate_host", "provider_action": "WORKLOAD_ISOLATE",
    "target": { "incident_id": "…", "workload_id": "…" }, "parameters": {},
    "created_at": "…", "expires_at": "…", "digest": "<64 hex over the immutable command>"
  },
  "mandate": {
    "tier": "tier_4", "tier_effective": "tier_4", "tier_resolution": "…", "tier_floor": 2,
    "basis": "…", "required_approvals": 2, "approval_floor": 1, "approvals_given": 2,
    "source": "fleet dispatch gate: 2 independent approval(s) the command authority recorded as MFA-bound required … MFA basis as the authority recorded it: edge_session. CCAS tier: tier_4."
  },
  "approval": {
    "authority": "soc_command_authority", "status": "approved",
    "revision": 2, "observed_at": "…", "required": 2, "required_effective": 2, "given": 2,
    "approvers": [ { "principal_hash": "<16 hex>", "role": "supervisor", "at": "…", "mfa_basis": "edge_session" }, { … } ]
  },
  "posture": { "posture": "normal", "revision": 7 }
}
```

| Field | Meaning |
|---|---|
| `schema`, `alg` | Fixed for v1. A verifier refuses any other value. |
| `attestation_id` | Unique per token; also written to the operator's HexaRecord audit chain with the dispatch intent, so a token can be matched to the operator's record. |
| `issued_at`, `expires_at` | UTC ISO-8601. TTL is 300 s — a token is for one dispatch, now. |
| `audience` | Host (netloc) of the exact provider URI being called. Refuse a token whose audience is not you. |
| `idempotency_key` | The 64-hex durable dispatch key; equals the `Idempotency-Key` header on the same request. Binds the token to one request. |
| `executor` | The executing agent's HexaID fields, copied from its signed `identity.json`. `identity_signed` is true only when the runtime verified the identity's Ed25519 chain at mint time (generator signature over the canonical identity, `generator.pub` and `root.pub` pins, root signature over the generator key). `identity_root_anchored` is true or false when the runtime pins a trusted root fingerprint, and null when it pins none (the chain was then checked for internal consistency only). A receiver that needs certainty verifies the identity itself with `verify_identity.py --trusted-root`. |
| `signer` | The attestation signing key. **Verify against the pin on `TRUST.md`, not this field**; a verifier additionally refuses a token whose embedded key differs from the pinned one (`signer_not_pinned`). |
| `command` | The immutable command and its digest. `target` and `parameters` are copied verbatim so the receiver can compare them with the request it is executing. |
| `mandate` | What this command executed under: `tier` is the CCAS tier the command authority recorded for the command; `tier_effective` is the tier the fleet enforced, `tier_resolution` how it was determined (a tier the fleet cannot determine is treated as tier 4) and `tier_floor` the approvals that tier requires; `basis` is the authority's stated basis; `required_approvals` is the count the fleet enforced (the strictest of the authority's count, the fleet floor and the tier floor); `approval_floor` is the fleet floor; `approvals_given` is the number of distinct approvers recorded. `source` restates these numbers and the recorded MFA basis in words. |
| `approval` | Fresh read of the customer's command authority at dispatch: `status` (as read from the authority), `revision` (approvals recorded), `required` (what the authority demanded), `required_effective` (what the fleet enforced), `given` (distinct approvers), `approvers` (hashed principal, role, time, and `mfa_basis` as the authority recorded it, null when it recorded none). `principal_hash` = `sha256(normalised principal_id)[:16]`, where normalised means Unicode NFKC, trimmed, internal whitespace collapsed to one space, case-folded. |
| `posture` | The customer's fleet posture and its revision at the commit window. Provider actions dispatch only under `normal`. |

## 6. Verification (normative)

A token is **valid** only if **all** of the following hold. Any failure ⇒ invalid; report every reason.

1. Well-formed: exactly two non-empty base64url parts; the first decodes to a JSON object.
2. `schema == "hexabox.action_attestation/v1"` and `alg == "ed25519"`.
3. The signature verifies over the **decoded payload bytes** under the **pinned** signer public key from `TRUST.md` (reason on failure: `bad_signature`). Use a hardened Ed25519 verifier: reject non-canonical point encodings, small-order public keys and `S ≥ L`.
4. `signer.pubkey_b64` equals the pinned key (`signer_not_pinned` otherwise).
5. `expires_at > now` (`expired`) and `issued_at ≤ now + 60 s` (`issued_in_future`); both parse (`bad_timestamps`).
6. If you know your host: `audience` equals it (`audience_mismatch`).
7. If you have the request: `idempotency_key` equals its `Idempotency-Key` header (`idempotency_key_mismatch`).
8. If you hold a HexaBox command record: `command.digest` equals it (`digest_mismatch`).
9. `approval.status == "approved"` and `approval.approvers` is a non-empty list (`no_approvals_attested`).

Recommended, outside the token: compare `command.target` with the target of the request you are executing; bind `executor.agent_id` to the agent you admitted; consult `revocations.json` on this channel when online.

```
python3 verifiers/verify_action_attestation.py \
    --token "$X_HEXAID_ATTESTATION" \
    --trusted-pubkey "<Action attestation signer, TRUST.md>" \
    --audience api.example.com --idempotency-key "$IDEMPOTENCY_KEY"
# exit 0 + {"valid": true, …}   or   exit 1 + {"valid": false, "reasons": [...]}
```

## 7. Keys, publication, rotation

* The attestation signer is an Ed25519 key held by the executing fleet runtime (`FLEET_ACTION_ATTESTATION_KEY`, seed only in the runtime's environment; never in logs, responses or the token). Its public key and `signer.id` are served by the runtime (`GET /fleet/action-attestation`) and **pinned on `TRUST.md`** on this channel. Only the pin is authoritative.
* Without a provisioned key the runtime sends **no header** and records `unsigned:FLEET_ACTION_ATTESTATION_KEY_not_set` on its audit chain with the dispatch. It never sends an unsigned or self-asserted token.
* Rotation: a new signer is announced on `TRUST.md` with both pins listed for the transition period; a verifier may accept any listed pin. A compromised signer is listed in `revocations.json`.
* One signer per instance is the v1 model. A multi-instance operator lists one pin per instance, each labelled with its `signer.id`.

## 8. Privacy

The token carries no credential, no bearer token, no incident content beyond the command's own target identifiers, and no person's name: approvers appear only as `principal_hash`. Everything in it is already in the receiver's hands (the request) or is governance metadata.

## 9. Relation to the rest of the HexaBox trust chain

| Artifact | Signed by | Verified with | Anchors to |
|---|---|---|---|
| `identity.json` (`hexabox.identity/v1`) | factory generator key, root-chained | `verify_identity.py --trusted-root` | root fingerprint on `TRUST.md` |
| **action attestation (`hexabox.action_attestation/v1`)** | **fleet attestation signer** | **`verify_action_attestation.py --trusted-pubkey`** | **signer pin on `TRUST.md`** |

## 10. Versioning

`schema` is the version. A v2 would be a new schema string; v1 verifiers refuse it (`bad_schema`). Fields are never removed or re-typed within v1; new optional fields may be added (a v1 verifier ignores unknown fields — the signature still covers them).
