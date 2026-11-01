# HexaBox agent identity — `hexabox.identity/v2`

An agent's `identity.json` is signed by the factory's generator key, and the generator key is signed by the root on `TRUST.md`. The signature covers the whole document (every field except `signature`, canonical JSON with sorted keys), so nothing in it can be changed without breaking the seal. `verify_identity.py` (reference copy in `verifiers/`) checks the seal, the root chain, the file manifest and the design hashes offline.

## What v2 adds (2026-11-01)

| Field | Meaning |
|---|---|
| `schema` | `hexabox.identity/v2`. A v1 identity has no key fields; both verify with the same verifier. |
| `agent_pubkey_b64` | The agent's own Ed25519 public key (32 bytes), inside the signed body. The factory thereby certifies *this key belongs to this agent*. The private half is provisioned on the agent's host (`FLEET_MEMBER_KEY`) and never leaves it. |
| `agent_key_id` | `sha256(agent_pubkey)[:16]`, the key id the agent writes into every signature it makes (door-2 deliveries, fleet signals, and for a Fleet Command instance the action attestation `signer.id`). |
| `conformance.design.node_identity_set_hash` | sha256 over the sorted list of the agent's node identities (below), signed with the rest of the design hashes. |

The verifier refuses a v2 identity whose `agent_key_id` does not equal `sha256(agent_pubkey)[:16]`, whose key is not a canonical point on the curve, or whose node identity set does not recompute from the signed karta.

At runtime the agent reports whether the key it signs with is the key its identity names (`GET /fleet/lease/status` → `identity_key_binding.state`: `bound`, `mismatch`, `identity_v1`, `no_member_key`).

## Lineage: node → agent → fleet (2026-11-02)

When an agent belongs to a fleet in Studio, its identity carries a signed `lineage` block:

| Field | Meaning |
|---|---|
| `lineage.fleet_id` | The Studio fleet (uuid) the agent belongs to. |
| `lineage.fleet_name` | The fleet's name at issue time. |
| `lineage.hub_agent_id` | The fleet's hub agent (the Fleet Command instance), or null. |
| `lineage.assigned_at` | When Studio bound the agent to the fleet. |

So every node can be traced: `node_identity` → the agent (`agent_id`, signed) → the fleet (`lineage`) → the fleet's hub. `lineage` is **descriptive**: it does not enable lease enforcement or any other gate. Enforcement is still derived only from `owner.fleet_id` / `fleet_managed` (fleet_trust.fleet_managed), which `lineage` never touches. A verifier refuses a `lineage` whose `fleet_id` is not a uuid or whose `fleet_name` is empty.

## Reissued identities (2026-11-02)

An agent that has been developed on after its birth (the SOC, the fleet, every specialist) gets its identity **reissued by Studio** from the repository at a named commit: Studio reads the repo, recomputes the file manifest and the design summary with the verifier's formulas, adds `lineage`, keeps the agent's key, and signs. The repository's code is never regenerated — the delivery is exactly three files (`identity.json`, `MANIFEST.json`, the two `.pub` pins) in a pull request. A design block created this way is marked `conformance.design.derived_at_reissue: true` with `design_source_commit`, so nobody reads it as the factory's original composition. Every issuance is recorded in Studio (`studio_identity_issuances`: agent, repo, commit, identity sha256, who, when, PR).

## Node identity

Every node of every agent has a stable, global identity, independent of the node's code (the code is bound separately by the signed file manifest and `provenance_hash`):

    node_identity = sha256("hexabox.node_identity/v1\n" + agent_id + "\n" + node_id).hexdigest()[:32]

New builds write it into `karta.compiled.json` (`topology.nodes[].node_identity`); for earlier bundles it is derived from the signed identity and karta. It is what a command proposal and a HexaID action attestation name when they say *which node* proposed an action (`proposal.node_identity`, see `ACTION_ATTESTATION.md`).

## One key per agent

A Fleet Command instance's identity key is its action-attestation signing key: the `signer.id` pinned on `TRUST.md` equals the `agent_key_id` in the instance's signed identity (`ae3aeb73b0c64f67` for instance `ds5777`). A specialist's identity key is the key it signs its door-2 deliveries with; the fleet's member registry binds the same key to the same `agent_id`.
