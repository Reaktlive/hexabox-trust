#!/usr/bin/env python3
"""Offline identity verifier for a HexaBox agent bundle.

Usage:  python verify_identity.py  [bundle_dir] [--trusted-root <64-hex>]

Reads identity.json + karta.compiled.json + generator.pub + root.pub from the
bundle, recomputes the provenance hash, and verifies the Ed25519 signature
chain WITHOUT any network access or third-party packages. Pure stdlib.

--trusted-root <64-hex>  (B9, external trust anchor) the sha256 of the root
    public key exactly as shipped in root.pub (base64 text, stripped) — obtain it
    from a channel OTHER than this bundle (docs/verify_root_fingerprint.md). With
    the pin the verifier FAILS on any bundle whose root is not the pinned root
    ('NOT ANCHORED', exit 1); without it the chain is verified for internal
    consistency only and the fingerprint is printed so you can compare it by hand.
    The flag may be given before or after the positional bundle_dir.

Exit codes and verdict (exactly ONE verdict line is printed):
  0  'genuine ✓ …'          signature, root chain, reports, design and the
                             signed file manifest all verify (and, with
                             --trusted-root, the root is the pinned root).
  1  'FAILED ✗ …'           any tamper, signature, chain, anchor or tree
                             failure — including a broken root chain, a
                             symlink anywhere in the tree, compiled Python
                             (*.pyc / __pycache__) outside the signed
                             runtime_outputs, and a manifest path that is not
                             a normalised relative path.
  2  'NOT VERIFIABLE ✗ …'   the bundle carries nothing to verify: an unsigned
                             handoff build (delivery_mode "handoff", signature
                             null) or a pending identity. Never exit 0.

Values this verifier reports but does not re-measure (e.g. build-purity) are
printed as the SIGNED value from identity.json, labelled "(signed)".
"""
from __future__ import annotations
import base64, fnmatch, hashlib, json, os, posixpath, sys
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
    # closes the small-order / identity-key acceptance (external DD reviewer finding): a
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
    """Phase 2.23 (external DD reviewer finding #5) — the SIGNED payload is the WHOLE identity
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


def not_verifiable(msg: str) -> None:
    print(f"NOT VERIFIABLE ✗ {msg}")
    sys.exit(2)


def parse_argv(argv: list) -> tuple:
    """Split the CLI arguments into (bundle_dir, trusted_root).

    `--trusted-root <64-hex>` may appear before or after the positional
    bundle_dir, and the plain positional form `verify_identity.py [dir]` is
    unchanged. bundle_dir is None when no positional was given (caller defaults
    to the script's own directory); trusted_root is None when the flag is
    absent, else the lower-cased 64-hex fingerprint. Raises ValueError on a
    missing or malformed fingerprint so the caller can fail closed.
    """
    argv = list(argv)
    trusted_root = None
    if "--trusted-root" in argv:
        _i = argv.index("--trusted-root")
        if _i + 1 >= len(argv):
            raise ValueError("--trusted-root requires a 64-hex sha256 fingerprint")
        trusted_root = argv[_i + 1].strip().lower()
        del argv[_i:_i + 2]
        if len(trusted_root) != 64 or any(c not in "0123456789abcdef" for c in trusted_root):
            raise ValueError("--trusted-root must be a 64-hex sha256 fingerprint")
    base = argv[0] if argv else None
    return base, trusted_root


def root_fingerprint(base: str):
    """sha256 of root.pub exactly as shipped (base64 text, stripped) — the
    definition docs/verify_root_fingerprint.md gives for the out-of-band compare.
    Returns None when root.pub is missing or unreadable."""
    try:
        return hashlib.sha256(open(os.path.join(base, "root.pub")).read().strip().encode()).hexdigest()
    except Exception:
        return None


def manifest_path_error(p: Any):
    """Why a manifest entry path is not acceptable, or None. A manifest path
    must be a RELATIVE, NORMALISED posix path inside the bundle: no absolute
    path, no drive, no backslash, no '.'/'..'/empty segment, no NUL — so a
    signed entry can never point the verifier outside the tree it checks."""
    if not isinstance(p, str) or not p:
        return "manifest entry path is missing or not a string"
    if "\x00" in p or "\\" in p:
        return f"manifest path {p!r} contains a NUL or backslash"
    if p.startswith("/") or os.path.isabs(p) or (len(p) > 1 and p[1] == ":"):
        return f"manifest path {p!r} is absolute"
    segs = p.split("/")
    if any(s in ("", ".", "..") for s in segs):
        return f"manifest path {p!r} is not normalised (empty, '.' or '..' segment)"
    if posixpath.normpath(p) != p:
        return f"manifest path {p!r} is not normalised"
    return None


# Directories that hold metadata only and may legitimately appear in a checked-
# out tree (a CI checkout's .git; pytest's cache; the *.egg-info of the shipped
# package's own editable install). They are skipped ONLY while they contain no
# executable Python and no symlink — anything else inside them is reported.
_METADATA_DIRS = (".git", ".pytest_cache")
_EXECUTABLE_SUFFIXES = (".py", ".pyc", ".pyo", ".pyd", ".so", ".pth")


def _metadata_dir_problem(path: str, rel: str):
    if os.path.basename(path) == ".git":
        return None  # version-control metadata; never imported, may be skipped
    for root, dirs, names in os.walk(path):
        for d in dirs:
            if os.path.islink(os.path.join(root, d)):
                return f"symlink inside skipped metadata dir {rel}: {os.path.relpath(os.path.join(root, d), path)}"
        for fn in names:
            full = os.path.join(root, fn)
            if os.path.islink(full):
                return f"symlink inside skipped metadata dir {rel}: {os.path.relpath(full, path)}"
            if fn.endswith(_EXECUTABLE_SUFFIXES):
                return f"executable Python inside skipped metadata dir {rel}: {os.path.relpath(full, path)}"
    return None


def scan_tree(base: str, runtime: list, measured: list, excluded: set):
    """Walk the delivered tree WITHOUT following symlinks. Returns
    (files, measured_seen, problems): the delivered file set (relative posix
    paths, minus signed exclusions / runtime_outputs / measured_outputs), the
    measured outputs found, and the tree problems that fail verification:
      * any symlink (file or directory) anywhere in the tree;
      * compiled Python (*.pyc / *.pyo or a __pycache__ directory) that is not
        covered by a SIGNED runtime_outputs pattern — a cached .pyc is
        imported instead of its source, so it is code the manifest never saw;
      * executable content or a symlink inside a skipped metadata directory.
    Only .git is skipped unconditionally."""
    def _rt(rel):
        return any(fnmatch.fnmatch(rel, pat) for pat in runtime)

    def _ms(rel):
        return any(fnmatch.fnmatch(rel, pat) for pat in measured)

    files, measured_seen, problems = set(), [], []
    for root, dirs, names in os.walk(base, followlinks=False):
        keep = []
        for d in sorted(dirs):
            full = os.path.join(root, d)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            if os.path.islink(full):
                problems.append(f"symlink (directory) in tree: {rel}")
                continue
            if d in _METADATA_DIRS or d.endswith(".egg-info"):
                prob = _metadata_dir_problem(full, rel)
                if prob:
                    problems.append(prob)
                continue
            if d == "__pycache__" and not _rt(rel + "/"):
                # report the directory itself; its contents are compiled code
                problems.append(f"compiled-Python cache directory in tree: {rel}")
                continue
            keep.append(d)
        dirs[:] = keep
        for fn in names:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            if os.path.islink(full):
                problems.append(f"symlink in tree: {rel}")
                continue
            if _ms(rel):
                measured_seen.append(rel)
                continue
            if rel in excluded or _rt(rel):
                continue
            if fn.endswith((".pyc", ".pyo")):
                problems.append(f"compiled Python in tree: {rel}")
                continue
            files.add(rel)
    return files, sorted(measured_seen), problems


def verify_manifest(base: str, mconf: dict, notes: list = None):
    """Re-verify the SIGNED file manifest. Returns an error string, or None on
    success (disclosures, e.g. measured supply-chain files, are appended to
    `notes` when a list is given). Factored out of main() so the manifest logic
    is testable without a live Ed25519 signature.

    The signature over identity.json covers `conformance` (see payload_for), and
    the manifest hash is sealed INSIDE conformance, so every delivered FILE is
    bound to the signed identity, not just the karta:
      (a) MANIFEST.json's files array must hash to the SIGNED manifest_sha256;
      (b) every listed path must be a normalised relative path, listed once,
          and exist as a regular file (not a symlink) with the EXACT size +
          sha256;
      (c) no UNLISTED delivered file and none missing — the disk set (minus the
          SIGNED exclusions, runtime_outputs and measured_outputs) must equal
          the manifest set — and the tree must be clean (no symlinks, no
          compiled Python outside runtime_outputs; see scan_tree).
    The exclusion, runtime_outputs and measured_outputs lists live INSIDE the
    signed conformance, so a tamperer cannot widen them.
    """
    signed_mhash = mconf.get("manifest_sha256")
    excluded = set(mconf.get("excluded") or [])
    runtime = list(mconf.get("runtime_outputs") or [])
    measured = list(mconf.get("measured_outputs") or [])
    try:
        mdoc = json.loads(open(os.path.join(base, "MANIFEST.json"), "rb").read())
    except Exception as e:
        return f"conformance carries a signed manifest but MANIFEST.json is unreadable: {e}"
    files = mdoc.get("files") if isinstance(mdoc, dict) else None
    if not isinstance(files, list):
        return "MANIFEST.json has no files array"
    # (a) the shipped files array must hash to the SIGNED manifest hash.
    recomputed = hashlib.sha256(canonical(files).encode("utf-8")).hexdigest()
    if recomputed != signed_mhash:
        return f"MANIFEST.json files hash {recomputed[:16]} != SIGNED manifest_sha256 {str(signed_mhash)[:16]} — manifest tampered"
    if mdoc.get("manifest_sha256") != signed_mhash:
        return "MANIFEST.json manifest_sha256 disagrees with SIGNED conformance.manifest — manifest tampered"
    if mconf.get("file_count") != len(files):
        return f"SIGNED file_count {mconf.get('file_count')} != MANIFEST.json files {len(files)}"
    # (b) every listed path normalised, unique, a regular file with exact size + hash.
    manifest_paths = set()
    for ent in files:
        p = ent.get("path") if isinstance(ent, dict) else None
        perr = manifest_path_error(p)
        if perr:
            return perr + " — manifest tampered"
        if p in manifest_paths:
            return f"manifest lists {p} more than once — manifest tampered"
        manifest_paths.add(p)
        full = os.path.join(base, p)
        if os.path.islink(full):
            return f"manifest lists {p} but it is a symlink — refusing to follow it (tampered)"
        try:
            fb = open(full, "rb").read()
        except Exception as e:
            return f"manifest lists {p} but it is missing/unreadable: {e}"
        if len(fb) != ent.get("size"):
            return f"{p}: size {len(fb)} != manifest {ent.get('size')} — file tampered"
        fh = hashlib.sha256(fb).hexdigest()
        if fh != ent.get("sha256"):
            return f"{p}: sha256 {fh[:16]} != manifest {str(ent.get('sha256'))[:16]} — file tampered"
    # (c) tree hygiene, then no added/unlisted delivered file and none removed.
    on_disk, measured_seen, problems = scan_tree(base, runtime, measured, excluded)
    if problems:
        return f"{len(problems)} tree problem(s) — tampered or unclean tree: {problems[:5]}"
    extra = sorted(on_disk - manifest_paths)
    missing = sorted(manifest_paths - on_disk)
    if extra:
        return f"{len(extra)} delivered file(s) NOT in the signed manifest (added/unlisted): {extra[:5]}"
    if missing:
        return f"{len(missing)} manifest file(s) missing on disk: {missing[:5]}"
    if measured_seen and notes is not None:
        notes.append("post-release measured supply-chain files present (declared in the SIGNED identity; "
                     f"validated by the shipped supply-chain verify job): {measured_seen}")
    return None


def main() -> None:
    try:
        base, trusted_root = parse_argv(sys.argv[1:])
    except ValueError as e:
        fail(str(e))
    if base is None:
        base = os.path.dirname(os.path.abspath(__file__))
    try:
        identity = json.loads(open(os.path.join(base, "identity.json")).read())
    except Exception as e:
        fail(f"cannot read identity.json: {e}")
    if not isinstance(identity, dict):
        fail("identity.json is not a JSON object")
    # delivery_mode HANDOFF — a customer-owned, UNSIGNED, editable build. It
    # carries delivery_mode == "handoff" and signature == null and makes NO
    # attestation claim: there is no signature chain and no signed manifest to
    # verify. It is reported as NOT VERIFIABLE and exits 2 — never 0, with or
    # without --trusted-root, so a script that treats exit 0 as "verified" can
    # never mistake an unsigned build for a genuine one.
    if identity.get("delivery_mode") == "handoff" and identity.get("signature") is None:
        not_verifiable("HANDOFF build (unsigned, editable) — no signature to verify, nothing is attested"
                       + (" — cannot anchor to --trusted-root" if trusted_root is not None else ""))
    if identity.get("signature_pending"):
        not_verifiable(f"identity is PENDING (no signature shipped): {identity.get('signature_pending_reason')}")
    if not isinstance(identity.get("signature"), str) or not identity.get("signature"):
        fail("identity.json carries no signature")

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

    try:
        gen_pub = base64.b64decode(identity["generator_pubkey_b64"])
        sig = base64.b64decode(identity["signature"])
    except Exception as e:
        fail(f"undecodable generator key or signature: {e}")

    # 3) verify the Ed25519 signature over the canonical payload
    if not ed25519_verify(gen_pub, sig, payload_for(identity)):
        fail("Ed25519 signature does not verify against generator public key")

    # 4) root-chain check — a broken chain FAILS (single verdict, exit 1)
    try:
        root_pub_disk = open(os.path.join(base, "root.pub")).read().strip()
    except FileNotFoundError:
        fail("root chain BROKEN — root.pub missing")
    except Exception as e:
        fail(f"root chain BROKEN — root.pub unreadable: {e}")
    if root_pub_disk != identity.get("root_pubkey_b64"):
        fail("root chain BROKEN — root.pub on disk does not match identity.json")
    try:
        chain_sig = base64.b64decode(identity["generator_pubkey_signed_by_root_b64"])
        root_pub = base64.b64decode(identity["root_pubkey_b64"])
    except KeyError:
        fail("root chain BROKEN — no root-chain fields in identity.json")
    except Exception as e:
        fail(f"root chain BROKEN — undecodable root-chain fields: {e}")
    if not ed25519_verify(root_pub, chain_sig, gen_pub):
        fail("root chain BROKEN — root signature on generator pubkey invalid")

    # 4b) B9 — external trust anchor. The root fingerprint is sha256 of root.pub
    # as shipped (base64 text, stripped) — the definition
    # docs/verify_root_fingerprint.md gives for the out-of-band compare. With
    # --trusted-root the compare is machine-enforced: a bundle whose root is not
    # the pinned root FAILS ('NOT ANCHORED') even if its internal chain is
    # consistent (a re-signed bundle under a foreign root). Without the flag the
    # fingerprint is still printed, marked unanchored, for a manual compare.
    root_fp = root_fingerprint(base)
    if trusted_root is not None:
        if root_fp is None:
            fail("root NOT ANCHORED — --trusted-root given but root.pub is missing/unreadable, cannot anchor")
        if root_fp != trusted_root:
            fail(f"root {root_fp[:16]}… NOT ANCHORED — does not match the trusted root {trusted_root[:16]}… — identity chain is anchored to an unknown root")

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

    # Phase 1.3 — multi-dimensional attestation: the artifact/build counts and
    # the release verdict are signed; the report must agree with them. A signed
    # identity must NEVER carry BLOCKED (the signing gate skips signing
    # on blocked builds — see the release gate in the factory).
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

    # Phase 2.8a — SIGNED DESIGN FINGERPRINT: the sets are RECOMPUTED from the bundle's
    # own artifacts (karta.compiled.json + capability_truth.json) and must
    # be identical to the signed hashes. A node, edge, capability or
    # action cannot be swapped, vanish or appear without breaking the design
    # identity — design changes are EXPLICIT, never silent.
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

    # Phase 2.13e — SIGNED FILE MANIFEST. Every delivered file (except the
    # structurally post-signature-excluded ones, listed SIGNED in
    # conformance.manifest.excluded) is hashed; the canonical manifest hash lives
    # in the Ed25519-signed conformance. This step catches a code change that
    # breaks no test (e.g. DEFAULT_RETENTION_DAYS 365->366) and runs
    # as verify_release step 1/3, BEFORE any bundle code is imported.
    notes = []
    _mconf = conf.get("manifest")
    if _mconf is not None:
        _merr = verify_manifest(base, _mconf, notes)
        if _merr:
            fail(_merr)
    for _n in notes:
        print(_n)

    purity = conf.get("purity_score", "?")
    pmax = conf.get("purity_max", "?")
    doctrine_ver = conf.get("doctrine_version", "?")
    dpass = conf.get("doctrine_pass", "?")
    dtot = conf.get("doctrine_total", "?")
    gen_id = identity.get("generator_id", "?")
    _fp_short = (root_fp[:16] + "…") if root_fp else "?"
    anchor_tag = (f"root {_fp_short} ANCHORED ✓ (matches --trusted-root)" if trusted_root is not None
                  else f"root {_fp_short} (unanchored — compare out-of-band or pass --trusted-root)")
    # The single verdict line. build-purity is the factory-measured value carried
    # in the SIGNED identity — printed, not re-measured here.
    print(
        f"genuine ✓ / doctrine {dpass}/{dtot} re-verified (v{doctrine_ver}) / build-purity {purity}/{pmax} (signed) / generator {gen_id} / root-chained ✓ / {anchor_tag}"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
