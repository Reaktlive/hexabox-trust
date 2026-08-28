#!/usr/bin/env python3
"""Offline identity verifier for a HexaBox agent bundle.

Usage:  python verify_identity.py  [bundle_dir] [--trusted-root <64-hex>]

Reads identity.json + karta.compiled.json + generator.pub + root.pub from the
bundle, recomputes the provenance hash, and verifies the Ed25519 signature
chain WITHOUT any network access or third-party packages. Pure stdlib.

--trusted-root <64-hex>  (B9, external trust anchor) the sha256 of the root
    public key exactly as shipped in root.pub (base64 text, stripped) — obtain it
    from a channel OTHER than this bundle (docs/verify_root_fingerprint.md). With
    the pin the verifier FAILS on any bundle whose root is not the pinned root;
    without it the chain is verified for internal consistency only and the
    fingerprint is printed so you can compare it by hand.

Exits 0 with 'genuine ✓' on success, 1 on any tamper / signature failure.
"""
from __future__ import annotations
import base64, hashlib, json, os, sys
from typing import Any


# ---------- minimal Ed25519 verify (RFC 8032, pure Python) ----------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = (4 * _inv(5)) % _p
_Bx = _xrecover(_By)
_B = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)


def _edwards_add(P, Q):
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = ((y1 - x1) * (y2 - x2)) % _p
    b = ((y1 + x1) * (y2 + x2)) % _p
    c = (t1 * 2 * _d * t2) % _p
    dd = (z1 * 2 * z2) % _p
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return ((e * f) % _p, (g * h) % _p, (f * g) % _p, (e * h) % _p)


def _scalarmult(P, e: int):
    if e == 0:
        return (0, 1, 1, 0)
    Q = _scalarmult(P, e // 2)
    Q = _edwards_add(Q, Q)
    if e & 1:
        Q = _edwards_add(Q, P)
    return Q


def _decodepoint(s: bytes):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1:
        x = _p - x
    P = (x, y, 1, (x * y) % _p)
    return P


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _isoncurve(P) -> bool:
    (x, y, z, t) = P
    return (z % _p != 0
            and (x * y) % _p == (z * t) % _p
            and (y * y - x * x - z * z - _d * t * t) % _p == 0)


def _is_identity(P) -> bool:
    # the neutral element in extended coords: x == 0 and y == z.
    (x, y, z, t) = P
    return x % _p == 0 and (y - z) % _p == 0


def _is_small_order(P) -> bool:
    # A point whose order divides the cofactor 8: [8]P is the identity. A genuine
    # public key has prime order L, so [8]A is never the identity. Rejecting these
    # closes the small-order / identity-key acceptance (external DD, Peter): a
    # small-order public key could otherwise satisfy the verification equation for
    # crafted signatures across multiple messages.
    return _is_identity(_scalarmult(P, 8))


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32:
        return False
    # Canonical point encoding: the y-coordinate must be < p (reject non-canonical
    # / over-p encodings that decode to the same point).
    if (int.from_bytes(signature[:32], "little") & ((1 << 255) - 1)) >= _p:
        return False
    if (int.from_bytes(public_key, "little") & ((1 << 255) - 1)) >= _p:
        return False
    try:
        R = _decodepoint(signature[:32])
        A = _decodepoint(public_key)
    except Exception:
        return False
    if not (_isoncurve(R) and _isoncurve(A)):
        return False
    # Reject small-order / identity public keys (a genuine member key is never
    # small-order); this is the check the previous verifier lacked.
    if _is_small_order(A):
        return False
    S = _decodeint(signature[32:])
    if S >= _L:
        return False
    h = _decodeint(_H(signature[:32] + public_key + message)) % _L
    R1 = _scalarmult(_B, S)
    R2 = _edwards_add(R, _scalarmult(A, h))
    # compare projective points by normalising
    (x1, y1, z1, _) = R1
    (x2, y2, z2, _) = R2
    return (x1 * z2 - x2 * z1) % _p == 0 and (y1 * z2 - y2 * z1) % _p == 0


# ---------- canonical JSON (matches edge-function signer) ----------
def canonical(v: Any) -> str:
    if v is None or isinstance(v, (bool, int, float, str)):
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False, sort_keys=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys())
        return "{" + ",".join(json.dumps(k) + ":" + canonical(v[k]) for k in keys) + "}"
    raise TypeError(f"uncanonicalisable type: {type(v)!r}")


def payload_for(identity: dict) -> bytes:
    """Fas 2.23 (external DD, Peter #5) — the SIGNED payload is the WHOLE identity
    minus the signature itself. Every field is covered: agent_id, generator_id,
    owner, provenance_hash, conformance AND capabilities, algorithm, schema,
    doctrine_version, signed_at, and the generator/root pubkeys + root-chain link.
    So a change to ANY byte of identity.json (previously capabilities/signed_at
    were unsigned) breaks the signature. The signer (agent-identity-sign edge
    function) signs the IDENTICAL canonical form — the two MUST stay in lockstep.
    Only "signature" is excluded (it cannot cover itself)."""
    core = {k: identity[k] for k in identity if k != "signature"}
    return canonical(core).encode("utf-8")


def fail(msg: str) -> None:
    print(f"FAILED ✗ {msg}")
    sys.exit(1)


def main() -> None:
    argv = list(sys.argv[1:])
    trusted_root = None
    if "--trusted-root" in argv:
        _i = argv.index("--trusted-root")
        if _i + 1 >= len(argv):
            fail("--trusted-root requires a 64-hex sha256 fingerprint")
        trusted_root = argv[_i + 1].strip().lower()
        del argv[_i:_i + 2]
        if len(trusted_root) != 64 or any(c not in "0123456789abcdef" for c in trusted_root):
            fail("--trusted-root must be a 64-hex sha256 fingerprint")
    base = argv[0] if argv else os.path.dirname(os.path.abspath(__file__))
    try:
        identity = json.loads(open(os.path.join(base, "identity.json")).read())
    except Exception as e:
        fail(f"cannot read identity.json: {e}")
    # delivery_mode HANDOFF — a customer-owned, UNSIGNED, editable build. It carries
    # delivery_mode == "handoff" and signature == null and makes NO attestation
    # claim, so there is no signature chain and no signed file manifest to verify.
    # Print a clear banner and exit 0 WITHOUT running the signature/manifest checks.
    # This is exactly what makes a handoff bundle freely editable (no signature to
    # break) AND what stops a handoff masquerading as sealed: a SEALED bundle never
    # has delivery_mode == "handoff" (a missing/invalid signature still FAILS below),
    # and a handoff bundle never carries a signature to trust.
    if identity.get("delivery_mode") == "handoff" and identity.get("signature") is None:
        print("HANDOFF (unsigned, editable) — not attested")
        sys.exit(0)
    if identity.get("signature_pending"):
        fail(f"identity is PENDING (no signature shipped): {identity.get('signature_pending_reason')}")

    # 1) recompute provenance_hash from karta.compiled.json (raw bytes)
    try:
        karta_bytes = open(os.path.join(base, "karta.compiled.json"), "rb").read()
    except Exception as e:
        fail(f"cannot read karta.compiled.json: {e}")
    recomputed = hashlib.sha256(karta_bytes).hexdigest()
    if recomputed != identity.get("provenance_hash"):
        fail(f"provenance hash mismatch — bundle tampered (got {recomputed[:16]}…, expected {str(identity.get('provenance_hash'))[:16]}…)")

    # 2) pin the generator public key to generator.pub on disk (defence vs editing identity.json)
    try:
        on_disk_pub = open(os.path.join(base, "generator.pub")).read().strip()
    except Exception as e:
        fail(f"cannot read generator.pub: {e}")
    if on_disk_pub != identity.get("generator_pubkey_b64"):
        fail("generator.pub on disk does not match identity.json generator_pubkey_b64")

    gen_pub = base64.b64decode(identity["generator_pubkey_b64"])
    sig = base64.b64decode(identity["signature"])

    # 3) verify the Ed25519 signature over the canonical payload
    if not ed25519_verify(gen_pub, sig, payload_for(identity)):
        fail("Ed25519 signature does not verify against generator public key")

    # 4) root-chain check (optional but present in v1 bundles)
    chain_ok = True
    chain_note = ""
    try:
        root_pub_disk = open(os.path.join(base, "root.pub")).read().strip()
        if root_pub_disk != identity.get("root_pubkey_b64"):
            chain_ok = False
            chain_note = " (root.pub on disk does not match identity.json)"
        else:
            chain_sig = base64.b64decode(identity["generator_pubkey_signed_by_root_b64"])
            root_pub = base64.b64decode(identity["root_pubkey_b64"])
            if not ed25519_verify(root_pub, chain_sig, gen_pub):
                chain_ok = False
                chain_note = " (root signature on generator pubkey invalid)"
    except KeyError:
        chain_ok = False
        chain_note = " (no root-chain fields in identity.json — pending)"
    except FileNotFoundError:
        chain_ok = False
        chain_note = " (root.pub missing — chain pending)"

    # B9 — external trust anchor. The root fingerprint is sha256 of root.pub as
    # shipped (base64 text, stripped) — the definition docs/verify_root_fingerprint.md
    # gives for the out-of-band compare. With --trusted-root the compare is
    # machine-enforced: a bundle whose root is not the pinned root FAILS even if
    # its internal chain is consistent (a re-signed bundle under a foreign root).
    root_fp = None
    try:
        root_fp = hashlib.sha256(open(os.path.join(base, "root.pub")).read().strip().encode()).hexdigest()
    except Exception:
        root_fp = None
    if trusted_root is not None:
        if root_fp is None:
            fail("--trusted-root given but root.pub is missing — cannot anchor")
        if root_fp != trusted_root:
            fail(f"root fingerprint {root_fp[:16]}… does not match the trusted root {trusted_root[:16]}… — identity chain is anchored to an unknown root")

    conf = identity.get("conformance") or {}
    # Cross-check the shipped CEVE report against the SIGNED conformance. The
    # report file is not itself signed, but the doctrine counts ARE (inside the
    # signed conformance) — so a report that disagrees with the signed
    # attestation is a forgery. Closes the "edit reports/ceve_validation.json and
    # still pass" hole.
    try:
        _rep = json.loads(open(os.path.join(base, "reports", "ceve_validation.json")).read())
    except Exception as e:
        fail(f"cannot read reports/ceve_validation.json: {e}")
    _rdoc = _rep.get("doctrine") or {}
    for _label, _got, _signed in (
        ("doctrine.pass_count", _rdoc.get("pass_count"), conf.get("doctrine_pass")),
        ("doctrine.reverified_offline", _rdoc.get("reverified_offline"), conf.get("doctrine_total")),
        ("doctrine.total_doctrine_gates", _rdoc.get("total_doctrine_gates"), conf.get("doctrine_total_gates")),
    ):
        if _signed is not None and _got != _signed:
            fail(f"reports/ceve_validation.json {_label}={_got} disagrees with SIGNED conformance ({_signed}) — report tampered")
    _dp, _dt = conf.get("doctrine_pass"), conf.get("doctrine_total")
    if isinstance(_dp, int) and isinstance(_dt, int) and _dt > 0:
        _expected = round(100 * _dp / _dt)
        if _rep.get("score") is not None and _rep.get("score") != _expected:
            fail(f"reports/ceve_validation.json score={_rep.get('score')} != score implied by SIGNED conformance ({_expected}) — report tampered")

    # Fas 1.3 — flerdimensionell attestering: artifact-/build-räkningarna och
    # release-verdicten är signerade; rapporten måste stämma med dem. En signerad
    # identitet får ALDRIG bära BLOCKED (signeringsgrinden hoppar över signering
    # på blockerade byggen — se release gate i fabriken).
    _rart = _rep.get("artifact_conformance") or {}
    _rbld = _rep.get("build_integrity") or {}
    for _label, _got, _signed in (
        ("artifact_conformance.pass_count", _rart.get("pass_count"), conf.get("artifact_pass")),
        ("artifact_conformance.warn_count", _rart.get("warn_count"), conf.get("artifact_warn")),
        ("artifact_conformance.fail_count", _rart.get("fail_count"), conf.get("artifact_fail")),
        ("artifact_conformance.na_count", _rart.get("na_count"), conf.get("artifact_na")),
        ("build_integrity.pass_count", _rbld.get("pass_count"), conf.get("build_pass")),
        ("build_integrity.fail_count", _rbld.get("fail_count"), conf.get("build_fail")),
    ):
        if _signed is not None and _got != _signed:
            fail(f"reports/ceve_validation.json {_label}={_got} disagrees with SIGNED conformance ({_signed}) — report tampered")
    _rv = conf.get("release_verdict")
    if _rv == "BLOCKED":
        fail("SIGNED conformance carries release_verdict=BLOCKED — a blocked build must never ship a signed identity")
    if _rv is not None and bool(_rep.get("build_blocked")) != (_rv == "BLOCKED"):
        fail(f"reports/ceve_validation.json build_blocked={_rep.get('build_blocked')} disagrees with SIGNED release_verdict={_rv}")

    # Fas 2.8a — SIGNERAD DESIGN-FINGERPRINT: mängderna räknas OM ur bundlens
    # egna artefakter (karta.compiled.json + capability_truth.json) och måste
    # vara identiska med de signerade hasharna. En nod, edge, capability eller
    # action kan inte bytas, försvinna eller tillkomma utan att design-
    # identiteten bryter — designändringar är EXPLICITA, aldrig tysta.
    _design = conf.get("design")
    if _design is not None:
        def _dhash(items):
            return hashlib.sha256(json.dumps(sorted(items), separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        try:
            _kc = json.loads(karta_bytes)
        except Exception as e:
            fail(f"cannot parse karta.compiled.json for design verification: {e}")
        _kt = _kc.get("topology") or {}
        _d_nodes = [str(n.get("id")) for n in (_kt.get("nodes") or [])]
        _d_edges = ["%s.%s->%s.%s%s" % (e.get("source_agent"), e.get("source_port"), e.get("target_agent"), e.get("target_port"), "#routing" if e.get("kind") == "routing" else "") for e in (_kt.get("edges") or [])]
        try:
            _ct = json.loads(open(os.path.join(base, "capability_truth.json")).read())
        except Exception as e:
            fail(f"cannot read capability_truth.json for design verification: {e}")
        _d_caps = ["%s=%s" % (n.get("id"), n.get("bucket")) for n in (_ct.get("nodes") or [])]
        _pa = ((_kc.get("metadata") or {}).get("privileged_actions")) or _kc.get("privileged_actions") or []
        _d_acts = ["%s@%s" % (a.get("name"), a.get("tier")) for a in _pa]
        for _label, _items, _signed in (
            ("node_set_hash", _d_nodes, _design.get("node_set_hash")),
            ("edge_set_hash", _d_edges, _design.get("edge_set_hash")),
            ("capability_set_hash", _d_caps, _design.get("capability_set_hash")),
            ("action_set_hash", _d_acts, _design.get("action_set_hash")),
        ):
            if _signed is not None and _dhash(_items) != _signed:
                fail(f"design fingerprint {_label} mismatch — the bundle's design differs from the SIGNED design identity (tampered or mixed artifacts)")
        for _label, _got, _signed in (
            ("node_count", len(_d_nodes), _design.get("node_count")),
            ("edge_count", len(_d_edges), _design.get("edge_count")),
        ):
            if _signed is not None and _got != _signed:
                fail(f"design fingerprint {_label}={_got} disagrees with SIGNED ({_signed})")

    # Fas 2.13e — SIGNERAT FILMANIFEST. Varje levererad fil (utom de
    # strukturellt-post-signatur-exkluderade, som listas SIGNERAT i
    # conformance.manifest.excluded) hashas; den kanoniska manifesthashen ligger
    # i den Ed25519-signerade conformance. Detta steg fangar en kodandring som
    # inte bryter nagot test (t.ex. DEFAULT_RETENTION_DAYS 365->366) och kors
    # som verify_release steg 1/3, INNAN nagon bundle-kod importeras.
    _mconf = conf.get("manifest")
    if _mconf is not None:
        _signed_mhash = _mconf.get("manifest_sha256")
        _excluded = set(_mconf.get("excluded") or [])
        try:
            _mdoc = json.loads(open(os.path.join(base, "MANIFEST.json"), "rb").read())
        except Exception as e:
            fail(f"conformance carries a signed manifest but MANIFEST.json is unreadable: {e}")
        _files = _mdoc.get("files")
        if not isinstance(_files, list):
            fail("MANIFEST.json has no files array")
        # (a) the shipped files array must hash to the SIGNED manifest hash
        _recomputed_mhash = hashlib.sha256(canonical(_files).encode("utf-8")).hexdigest()
        if _recomputed_mhash != _signed_mhash:
            fail(f"MANIFEST.json files hash {_recomputed_mhash[:16]} != SIGNED manifest_sha256 {str(_signed_mhash)[:16]} - manifest tampered")
        if _mdoc.get("manifest_sha256") != _signed_mhash:
            fail("MANIFEST.json manifest_sha256 disagrees with SIGNED conformance.manifest - manifest tampered")
        if _mconf.get("file_count") != len(_files):
            fail(f"SIGNED manifest file_count {_mconf.get('file_count')} != MANIFEST.json files {len(_files)}")
        # (b) every listed file must exist with the EXACT size + sha256
        _manifest_paths = set()
        for _ent in _files:
            _p = _ent.get("path")
            _manifest_paths.add(_p)
            try:
                _fb = open(os.path.join(base, _p), "rb").read()
            except Exception as e:
                fail(f"manifest lists {_p} but it is missing/unreadable: {e}")
            if len(_fb) != _ent.get("size"):
                fail(f"{_p}: size {len(_fb)} != manifest {_ent.get('size')} - file tampered")
            _fh = hashlib.sha256(_fb).hexdigest()
            if _fh != _ent.get("sha256"):
                fail(f"{_p}: sha256 {_fh[:16]} != manifest {str(_ent.get('sha256'))[:16]} - file tampered")
        # (c) no UNLISTED delivered file (added code) and none removed: the disk
        # set (minus the SIGNED exclusions, the SIGNED runtime_outputs, and
        # runtime-generated dirs) must equal the manifest path set. runtime_outputs
        # are files the bundle's OWN tooling writes when it runs (audit log, engine
        # reports, eval outputs) — they ship in no zip, so a verify run AFTER
        # execution must not read them as tampering. The list is SIGNED, so it
        # cannot be widened by a tamperer.
        import fnmatch
        _runtime = list(_mconf.get("runtime_outputs") or [])
        def _is_runtime_output(rel):
            return any(fnmatch.fnmatch(rel, pat) for pat in _runtime)
        # Fas 2.14b — SIGNED measured_outputs: post-release supply-chain material
        # the SHIPPED CI measures and commits (hashed lock, SBOM, base digest).
        # Ignored in the sweep like runtime_outputs, but DISCLOSED below when
        # present — silent tolerance would be a hole; the shipped supply-chain
        # verify job validates their CONTENT fail-closed. The list is SIGNED, so
        # a tamperer cannot widen it.
        _measured = list(_mconf.get("measured_outputs") or [])
        def _is_measured_output(rel):
            return any(fnmatch.fnmatch(rel, pat) for pat in _measured)
        _measured_seen = []
        # *.egg-info is deterministic in-tree debris of the SHIPPED package's own
        # editable install (pip install -e . — run by the bundle's CI and by
        # verify_release). Metadata only, never imported at runtime — same
        # category as __pycache__ (Fas 2.14b: surfaced when the supply-chain
        # verify leg ran the editable install before a re-verify).
        _IGNORE_SEG = ("__pycache__", ".pytest_cache", ".git")
        _on_disk = set()
        for _root, _dirs, _fnames in os.walk(base):
            _dirs[:] = [d for d in _dirs if d not in _IGNORE_SEG and not d.endswith(".egg-info")]
            for _fn in _fnames:
                _rel = os.path.relpath(os.path.join(_root, _fn), base).replace(os.sep, "/")
                if _is_measured_output(_rel):
                    _measured_seen.append(_rel)
                    continue
                if _rel.endswith(".pyc") or _rel in _excluded or _is_runtime_output(_rel):
                    continue
                _on_disk.add(_rel)
        _extra = sorted(_on_disk - _manifest_paths)
        _missing = sorted(_manifest_paths - _on_disk)
        if _extra:
            fail(f"{len(_extra)} delivered file(s) NOT in the signed manifest (added/unlisted): {_extra[:5]}")
        if _missing:
            fail(f"{len(_missing)} manifest file(s) missing on disk: {_missing[:5]}")
        if _measured_seen:
            print(f"post-release measured supply-chain files present (declared in the SIGNED identity; validated by the shipped supply-chain verify job): {sorted(_measured_seen)}")

    purity = conf.get("purity_score", "?")
    pmax = conf.get("purity_max", "?")
    doctrine_ver = conf.get("doctrine_version", "?")
    dpass = conf.get("doctrine_pass", "?")
    dtot = conf.get("doctrine_total", "?")
    gen_id = identity.get("generator_id", "?")
    chain_tag = "root-chained ✓" if chain_ok else f"root-chain BROKEN{chain_note}"
    _fp_short = (root_fp[:16] + "…") if root_fp else "?"
    anchor_tag = (f"root {_fp_short} ANCHORED ✓ (matches --trusted-root)" if trusted_root is not None
                  else f"root {_fp_short} (unanchored — compare out-of-band or pass --trusted-root)")
    print(
        f"genuine ✓ / doctrine {dpass}/{dtot} re-verified (v{doctrine_ver}) / build-purity {purity}/{pmax} / generator {gen_id} / {chain_tag} / {anchor_tag}"
    )
    sys.exit(0 if chain_ok else 1)  # broken root chain now FAILS (was exit 0)


if __name__ == "__main__":
    main()
