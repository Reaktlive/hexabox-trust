"""fleet_manifest — build + verify a SIGNED fleet manifest (DD P0, generic).

The external DD review's P1: the outer fleet package was not cryptographically
bound — eight individually-genuine bundles, but nothing tying them into one
attested fleet. This tool closes that, and it is the SAME document the runtime
coordinator trusts as its member registry (fleet_trust.load_registry): one
source of truth, two fidelities.

Generic cross-vertical machinery — no domain assumption. A manifest binds:
  * each member: agent_id, karta_hash, doctrine_version, fleet pubkey, and the
    delivered-artifact hashes (bundle zip / conformance pdf / dev plan);
  * the coordinator agent id;
  * the FleetSignal envelope version + the fleet k-policy;
  * the shared generator + root fingerprints;
  * an Ed25519 signature over the canonical manifest body.

verify_manifest re-derives every hash from the delivered files and checks the
signature — a receiver needs no trust in us, only the fleet public key supplied
out of band (the external trust anchor the DD asks for).

Usage:
    build_manifest(members, coordinator, out_path, sign) -> dict
    verify_manifest(manifest, files_root, verify_sig) -> (ok, reasons)

`sign(canonical_bytes) -> hex` and `verify_sig(canonical_bytes, sig_hex) -> bool`
are injected (Ed25519 in production; the CLI wires the pure-python signer).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Callable, Optional, Tuple

FLEET_MANIFEST_VERSION = "fleet_manifest/v1"


def sha256_file(path: str | os.PathLike) -> Optional[str]:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _read_json(path: str | os.PathLike) -> dict:
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def member_binding(bundle_dir: str | os.PathLike, *, pubkey_hex: str,
                   zip_path: Optional[str] = None, pdf_path: Optional[str] = None,
                   plan_path: Optional[str] = None, tenant_id: Optional[str] = None) -> dict:
    """Derive one member's binding from its bundle on disk + the provisioned
    fleet public key + the delivered artifact paths. karta_hash is the sha256 of
    the member's compiled karta — the exact value the coordinator's attestation
    checks against."""
    root = Path(bundle_dir)
    identity = _read_json(root / "identity.json")
    doctrine_version = str(identity.get("rules_version") or identity.get("doctrine_version") or "")
    # FTC-2: the member's declared privileged-action capabilities — the exact
    # scope the coordinator mints a lease for, and the scope the member's CCAS
    # gate checks each action against. Derived from the SIGNED compiled karta.
    karta = _read_json(root / "karta.compiled.json")
    _pa = ((karta.get("metadata") or {}).get("privileged_actions") or []) if isinstance(karta, dict) else []
    capability_scope = sorted({
        str(a.get("name") or a.get("action") or a.get("canonical_action") or "")
        for a in _pa if isinstance(a, dict) and (a.get("name") or a.get("action") or a.get("canonical_action"))
    })
    return {
        "agent_id": str(identity.get("agent_id") or ""),
        "karta_hash": sha256_file(root / "karta.compiled.json") or "",
        "doctrine_version": doctrine_version,
        "pubkey_hex": str(pubkey_hex),
        "capability_scope": capability_scope,
        # WS-1 (reviewer #4): the REAL operating tenant this member is deployed
        # for — the coordinator's k counts DISTINCT tenants, never agent ids. An
        # operator binds it at manifest time; absent => the member is recorded
        # but never counted toward k (never silently its own tenant).
        "tenant_id": str(tenant_id) if tenant_id else "",
        # DD review v2 (Peter #6): the SIGNED identity names the fleet by a factory
        # UUID (owner.fleet_id); the manifest/registry/leases name it by the
        # operational slug. Carry the UUID per member so the manifest can bind
        # the two namespaces explicitly (see build_manifest fleet_identity_uuid).
        "identity_fleet_uuid": str(((identity.get("owner") or {}).get("fleet_id")) or ""),
        "generator_fingerprint": str(identity.get("generator_fingerprint") or identity.get("generator_id") or ""),
        "root_fingerprint": str(identity.get("root_fingerprint") or identity.get("root_id") or ""),
        "artifacts": {
            "bundle_zip_sha256": sha256_file(zip_path) if zip_path else None,
            "conformance_pdf_sha256": sha256_file(pdf_path) if pdf_path else None,
            "dev_plan_sha256": sha256_file(plan_path) if plan_path else None,
        },
    }


def canonical_manifest_bytes(manifest: dict) -> bytes:
    """The canonical body the signature covers: the manifest minus the signature
    envelope. Sorted-key JSON, deterministic across languages."""
    body = {k: v for k, v in manifest.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_manifest(*, fleet_id: str, coordinator_agent_id: str, members: list,
                   fleet_signal_version: str, k_policy: dict,
                   sign: Callable[[bytes], str], signer_pubkey_hex: str,
                   lease_pubkey_hex: str = "", lease_epoch: int = 1,
                   e2e_result: Optional[dict] = None) -> dict:
    """Assemble and SIGN a fleet manifest. `members` is a list of member_binding
    dicts. The signature is over the canonical body; the fleet public key is
    embedded for convenience but a receiver must obtain it out of band to trust
    it (the external anchor).

    FTC-2: lease_pubkey_hex is the coordinator's PUBLIC lease-verification key
    (the private half lives ONLY on the coordinator, never in the manifest); it
    is bound into the SIGNED body so members verify leases against the attested
    key. lease_epoch lets the coordinator revoke all outstanding leases at once."""
    manifest = {
        "manifest_version": FLEET_MANIFEST_VERSION,
        "fleet_id": str(fleet_id),
        "coordinator_agent_id": str(coordinator_agent_id),
        "fleet_signal_version": str(fleet_signal_version),
        "k_policy": dict(k_policy or {}),
        "members": sorted(members, key=lambda m: str(m.get("agent_id"))),
        "e2e_result": e2e_result or {"status": "not_recorded"},
        "signer_pubkey_hex": str(signer_pubkey_hex),
        "lease_pubkey_hex": str(lease_pubkey_hex),
        "lease_epoch": int(lease_epoch),
    }
    # DD review v2 (Peter #6): ONE signed alias between the two fleet-id
    # namespaces. Every member's signed identity must carry the same
    # owner.fleet_id; that UUID is bound here as fleet_identity_uuid next to the
    # operational slug (fleet_id). A member from another fleet, or an identity
    # without a fleet, cannot be bound.
    uuids = {str(m.get("identity_fleet_uuid") or "") for m in members}
    if len(uuids) != 1 or "" in uuids:
        raise ValueError("members do not share one signed owner.fleet_id: %r" % sorted(uuids))
    manifest["fleet_identity_uuid"] = uuids.pop()
    # Bind the runtime member-registry projection into the SIGNED body, so a
    # receiver can prove the registry the coordinator loads is exactly the one
    # this manifest attests — not a separately-editable side file.
    manifest["registry_sha256"] = _registry_sha256(manifest)
    manifest["signature"] = {"alg": "ed25519", "sig": sign(canonical_manifest_bytes(manifest))}
    return manifest


def _registry_sha256(manifest: dict) -> str:
    reg = to_registry(manifest)
    return hashlib.sha256(
        json.dumps(reg, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def to_registry(manifest: dict) -> dict:
    """Project the manifest into the runtime member registry the coordinator
    loads (fleet_trust.FLEET_MEMBER_REGISTRY). One source of truth."""
    members = {}
    for m in manifest.get("members", []) or []:
        aid = str(m.get("agent_id"))
        if not aid:
            continue
        members[aid] = {
            "karta_hash": m.get("karta_hash"),
            "doctrine_version": m.get("doctrine_version"),
            "pubkey_hex": m.get("pubkey_hex"),
            # FTC-2: the member's declared capability scope travels into the
            # runtime registry so the coordinator mints an exactly-scoped lease.
            "capability_scope": m.get("capability_scope") or [],
            # WS-1: the bound operating tenant (k counts distinct tenants).
            "tenant_id": m.get("tenant_id") or "",
        }
    return {
        "fleet_id": manifest.get("fleet_id"),
        "doctrine_version": (manifest.get("members") or [{}])[0].get("doctrine_version") if manifest.get("members") else "",
        # FTC-2: the coordinator's PUBLIC lease key + the revocation epoch, so
        # the registry the coordinator loads carries the trust anchor for leases.
        "lease_pubkey_hex": manifest.get("lease_pubkey_hex") or "",
        "lease_epoch": manifest.get("lease_epoch") if manifest.get("lease_epoch") is not None else 1,
        # WS-1 (reviewer #4): the SIGNED k-policy travels into the runtime
        # registry — fleet_trust.fleet_k_floor() makes it the runtime authority
        # (max(code constant, signed floor)); an unsigned edit is refused at load.
        "k_policy": dict(manifest.get("k_policy") or {}),
        "members": members,
    }


def verify_manifest(manifest: dict, *, files_root: Optional[str] = None,
                    verify_sig: Callable[[bytes, str], bool],
                    artifact_paths: Optional[dict] = None,
                    expected_members: Optional[int] = None,
                    runtime_registry: Optional[dict] = None) -> Tuple[bool, list]:
    """FAIL-CLOSED verification. A missing check is a FAILURE, never a skip:

      * manifest version + Ed25519 signature over the canonical body;
      * structural completeness — members present, agent_ids unique, the
        coordinator is a member, all members share one generator + root
        fingerprint, and every member carries all four bound hashes
        (karta + zip + pdf + plan) — a null artifact hash is a failure;
      * `expected_members` exact count (when given);
      * the bound registry_sha256 matches the recomputed registry projection,
        and (when given) the runtime registry equals that projection exactly;
      * when files are available, every karta + artifact hash re-derives from
        disk (artifact_paths: agent_id -> {"bundle_dir","zip","pdf","plan"}).
    """
    reasons: list = []
    if manifest.get("manifest_version") != FLEET_MANIFEST_VERSION:
        reasons.append("bad_manifest_version:" + str(manifest.get("manifest_version")))

    sig = (manifest.get("signature") or {}).get("sig")
    if not sig:
        reasons.append("missing_signature")
    else:
        try:
            ok = bool(verify_sig(canonical_manifest_bytes(manifest), str(sig)))
        except Exception:
            ok = False
        if not ok:
            reasons.append("bad_signature")

    members = manifest.get("members") or []
    if not members:
        reasons.append("no_members")
    if expected_members is not None and len(members) != int(expected_members):
        reasons.append("member_count:%d!=%d" % (len(members), int(expected_members)))

    ids = [str(m.get("agent_id") or "") for m in members]
    if any(not i for i in ids):
        reasons.append("member_missing_agent_id")
    if len(set(ids)) != len(ids):
        reasons.append("duplicate_member_agent_id")

    coord = str(manifest.get("coordinator_agent_id") or "")
    if not coord or coord not in set(ids):
        reasons.append("coordinator_not_a_member:" + coord)

    # DD review v2 (Peter #6): the signed fleet_identity_uuid must equal every
    # member's identity_fleet_uuid — the explicit alias between the identity
    # UUID namespace and the operational slug. Missing or mismatched = failure.
    fuuid = str(manifest.get("fleet_identity_uuid") or "")
    if not fuuid:
        reasons.append("missing_fleet_identity_uuid")
    for m in members:
        if str(m.get("identity_fleet_uuid") or "") != fuuid:
            reasons.append("fleet_identity_uuid_mismatch:" + str(m.get("agent_id")))

    gens = {str(m.get("generator_fingerprint") or "") for m in members}
    roots = {str(m.get("root_fingerprint") or "") for m in members}
    if len(gens) != 1 or "" in gens:
        reasons.append("generator_fingerprint_not_shared:" + ",".join(sorted(gens)))
    if len(roots) != 1 or "" in roots:
        reasons.append("root_fingerprint_not_shared:" + ",".join(sorted(roots)))

    # Every member must carry ALL four bound hashes — a null is a failure.
    for m in members:
        aid = str(m.get("agent_id") or "?")
        if not m.get("karta_hash"):
            reasons.append("missing_karta_hash:" + aid)
        arts = m.get("artifacts") or {}
        for art in ("bundle_zip_sha256", "conformance_pdf_sha256", "dev_plan_sha256"):
            if not arts.get(art):
                reasons.append("missing_" + art + ":" + aid)

    # Registry binding: the bound hash must match the recomputed projection.
    bound = manifest.get("registry_sha256")
    recomputed_reg = _registry_sha256(manifest)
    if not bound:
        reasons.append("missing_registry_sha256")
    elif bound != recomputed_reg:
        reasons.append("registry_sha256_mismatch")
    if runtime_registry is not None:
        rr = hashlib.sha256(
            json.dumps(to_registry(manifest), sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        got = hashlib.sha256(
            json.dumps(runtime_registry, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        if got != rr:
            reasons.append("runtime_registry_mismatch")

    paths = artifact_paths or {}
    for m in manifest.get("members", []) or []:
        aid = str(m.get("agent_id"))
        p = paths.get(aid) if isinstance(paths, dict) else None
        if not p:
            continue
        bundle_dir = p.get("bundle_dir")
        if bundle_dir:
            recomputed = sha256_file(Path(bundle_dir) / "karta.compiled.json")
            if recomputed and recomputed != m.get("karta_hash"):
                reasons.append("karta_hash_mismatch:" + aid)
            ident = _read_json(Path(bundle_dir) / "identity.json")
            if str(ident.get("agent_id") or "") != aid:
                reasons.append("agent_id_mismatch:" + aid)
            if str(((ident.get("owner") or {}).get("fleet_id")) or "") != str(manifest.get("fleet_identity_uuid") or ""):
                reasons.append("identity_fleet_uuid_not_bound:" + aid)
        for key, art in (("zip", "bundle_zip_sha256"), ("pdf", "conformance_pdf_sha256"), ("plan", "dev_plan_sha256")):
            if p.get(key):
                recomputed = sha256_file(p[key])
                claimed = (m.get("artifacts") or {}).get(art)
                if claimed and recomputed and recomputed != claimed:
                    reasons.append(art + "_mismatch:" + aid)

    return (len(reasons) == 0, reasons)
