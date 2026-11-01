# Enrollment of an external agent (`POST /fleet/enroll`)

An agent that was not built by a fleet's own factory can ask to become a member only by presenting a signed identity (`IDENTITY.md`) whose root is on the fleet's accepted list (`TRUST.md` → *Accepted roots*). The door (`runtime/fleet_api/enroll.py` in Fleet Command) verifies the whole chain with nothing from disk — the generator's signature over the canonical identity, the root's signature over the generator key, and for v2 the agent key binding — and refuses any root that is not accepted. The member key the agent presents must be the key its identity names (v2); a v1 identity is recorded as `unprovable_v1`.

A genuine chain yields a **pending** enrollment record (append-only ledger + HexaRecord entry). The door never issues a lease, never grants scope and never writes the deploy-managed member registry: pending → active is an operator decision through the deploy records. The door is dark unless `FLEET_ENROLLMENT_ENABLED=1`.

Request: `{identity, manifest_sha256, member_pubkey_hex, requested_scope[]}`. Responses: 201 pending record · 403 identity not accepted (reason named) · 422 malformed request · 404 door closed.
