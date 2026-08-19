#!/usr/bin/env python3
"""verify_fleet_manifest — receiver walk over the signed fleet manifest.

Run from inside 00_Fleet/:

    python3 verify_fleet_manifest.py --trusted-pubkey <64-hex received out-of-band> --expected-members <N from the delivery documentation>
    (or FLEET_TRUSTED_PUBKEY=<64-hex> FLEET_EXPECTED_MEMBERS=<N> python3 verify_fleet_manifest.py)

Checks, fail-closed:
  1. the Ed25519 signature over the canonical manifest body, against the
     PINNED signer key (never against the key embedded in the manifest);
  2. every delivered artifact hash (agent bundle zip, conformance PDF, dev plan)
     re-derived from the sibling agent folders;
  3. every member's karta_hash re-derived by extracting the bundle zip, its
     signed identity's owner.fleet_id == the manifest's fleet_identity_uuid,
     and the bundle's own verify_identity.py re-run;
  4. the recorded E2E result re-hashed and compared to the signed anchor.

No third-party dependencies — pure standard library + the two local modules
(fleet_manifest.py, ed25519_verify.py) shipped alongside.

TRUST NOTE: the trust anchor is MANDATORY and EXTERNAL. Without --trusted-pubkey
or FLEET_TRUSTED_PUBKEY the verifier refuses to run (exit 2). The embedded
`signer_pubkey_hex` is only compared against the pin — a manifest carrying a
different key is refused before any hashing. The receiver obtains the pin (and
this verifier's digest) on a separate channel. This package ships a
clearly-marked DEMO signing key (see the manifest `_demo_note`); a production
fleet is signed with a key held off the delivery host.
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True  # never leave a __pycache__ behind in a delivered tree


def _load_source(name, path):
    """Load a sibling module FROM SOURCE (compile + exec) — bypassing any
    __pycache__/*.pyc the interpreter would prefer (DD review v4, P0)."""
    import types
    mod = types.ModuleType(name); mod.__file__ = path
    exec(compile(open(path, "rb").read(), path, "exec"), mod.__dict__)
    return mod


fm = _load_source("fleet_manifest", os.path.join(HERE, "fleet_manifest.py"))
ed25519_verify = _load_source("ed25519_verify", os.path.join(HERE, "ed25519_verify.py")).ed25519_verify

ROOT = os.path.dirname(HERE)  # the Fleet_Agents_* directory (00_Fleet's parent)


def sha256_file(path):
    try:
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    except OSError:
        return None


def _safe_extractall(zf, dest):
    """Extract with an explicit path-containment check: every resolved target
    must stay inside dest. Python's zipfile already sanitizes absolute paths and
    '..' components; this makes the guarantee explicit and fail-closed instead
    of implicit (DD review 2026-08-15)."""
    dest_real = os.path.realpath(dest)
    for info in zf.infolist():
        target = os.path.realpath(os.path.join(dest, info.filename))
        if not (target == dest_real or target.startswith(dest_real + os.sep)):
            raise RuntimeError("zip entry escapes extraction dir: %r" % info.filename)
    zf.extractall(dest)


def _bundle_root(extract_dir):
    """The directory containing identity.json inside an extracted bundle — the
    zip may hold the bundle at its top level or under a single wrapper folder."""
    for base, _dirs, files in os.walk(extract_dir):
        if "identity.json" in files:
            return base
    return None


def find_folder_files(folder):
    """Return (zip, pdf, plan, dupes) — each artifact path or None, plus a list of
    (label, count) for any artifact that is NOT present EXACTLY once. Picking the
    first of several silently would let a stray extra zip/pdf/plan ride along
    unverified, so a count != 1 is surfaced as a failure (Peter DD)."""
    d = os.path.join(ROOT, folder)
    z = glob.glob(os.path.join(d, "*.zip"))
    p = glob.glob(os.path.join(d, "HexaBox_Conformance_*.pdf"))
    pl = glob.glob(os.path.join(d, "Development_Plan_*.md"))
    dupes = [(label, len(g)) for label, g in (("zip", z), ("pdf", p), ("plan", pl)) if len(g) != 1]
    return (z[0] if z else None, p[0] if p else None, pl[0] if pl else None, dupes)


# Expected member count is a delivery fact the receiver reads from the package
# documentation and supplies OUT OF BAND — like the pin. It is deliberately not
# read from the manifest (a manifest can bind any number of members) and not
# hard-coded (the tool is generic across fleets). Without it the verifier
# REFUSES to run (exit 2), so an incomplete or padded fleet cannot pass.
def resolve_expected_members(argv, env_var="FLEET_EXPECTED_MEMBERS"):
    raw = None
    if "--expected-members" in argv:
        i = argv.index("--expected-members")
        raw = argv[i + 1] if i + 1 < len(argv) else None
    raw = (raw or os.environ.get(env_var, "")).strip()
    if not raw:
        print("FLEET MANIFEST: REFUSED — expected member count not supplied. Read it from the delivery "
              f"documentation and pass --expected-members <N> (or {env_var}=<N>). The count in the manifest "
              "itself is what is being verified and cannot be its own reference.")
        sys.exit(2)
    if not raw.isdigit() or int(raw) < 1:
        print("FLEET MANIFEST: REFUSED — --expected-members must be a positive integer.")
        sys.exit(2)
    return int(raw)

# Public key of the DEMO fleet-manifest seed (sha256("DEMO-FLEET-MANIFEST-KEY-2026-08-14")).
DEMO_FLEET_PUBKEY_HEX = "b8234b47b145e58d58f27cebdde141624bb9c0aa83e0a3af42fbdc91d2b3c3cc"


def resolve_trusted_pubkey(argv, env_var, embedded_hex, label):
    """The trust anchor is MANDATORY and EXTERNAL (DD P0, external review v2,
    2026-08-15): a public key read out of the very document being verified is
    not a trust anchor — an attacker who rewrites the manifest rewrites the key
    and the signature together, and the verifier prints PASS. So:
      * the key MUST be supplied out-of-band: --trusted-pubkey <64-hex> or the
        env var; with neither, the verifier REFUSES to run (exit 2), it does
        not fall back to the embedded key;
      * the embedded signer_pubkey_hex must EQUAL the pinned key — a manifest
        whose embedded key differs from the pin is refused before any hashing.
    The receiver obtains the pin on a separate channel (README 'Trust anchor')."""
    pin = None
    if "--trusted-pubkey" in argv:
        i = argv.index("--trusted-pubkey")
        pin = argv[i + 1] if i + 1 < len(argv) else None
    pin = (pin or os.environ.get(env_var, "")).strip().lower()
    if not pin:
        print(f"{label}: REFUSED — no trust anchor. Supply the signer public key out-of-band: "
              f"--trusted-pubkey <64-hex> (or {env_var}=<64-hex>). The key embedded in the manifest is "
              f"NOT used as an anchor.")
        sys.exit(2)
    try:
        if len(bytes.fromhex(pin)) != 32:
            raise ValueError
    except ValueError:
        print(f"{label}: REFUSED — trusted pubkey must be 32 bytes / 64 hex chars.")
        sys.exit(2)
    if str(embedded_hex or "").lower() != pin:
        print(f"{label}: FAIL — manifest signer_pubkey_hex does not match the trusted pin "
              f"(embedded {str(embedded_hex)[:16]}… vs pinned {pin[:16]}…). Manifest refused.")
        sys.exit(1)
    return pin


def main():
    manifest = json.load(open(os.path.join(HERE, "fleet_manifest.json")))
    pub = resolve_trusted_pubkey(sys.argv, "FLEET_TRUSTED_PUBKEY", manifest.get("signer_pubkey_hex", ""),
                                 "FLEET MANIFEST")

    def verify_sig(body, sig_hex):
        try:
            return ed25519_verify(bytes.fromhex(pub), bytes.fromhex(sig_hex), body)
        except Exception:
            return False

    # Fail-closed core: signature + structure + registry binding via the library.
    # Missing artifacts, wrong member count, coordinator-not-a-member, unshared
    # fingerprints, or a runtime-registry mismatch are FAILURES, not skips.
    # DD P0 (external review 2026-08-15): a MISSING or unreadable runtime registry
    # is itself a FAILURE — passing None into verify_manifest would silently skip
    # the registry comparison and print a PASS line that claims it was checked.
    # The registry file is a delivered artifact of this package; its absence is
    # tamper/incompleteness, never a skip.
    pre_reasons = []
    try:
        runtime_registry = json.load(open(os.path.join(HERE, "fleet_member_registry.json")))
    except (OSError, ValueError):
        runtime_registry = None
        pre_reasons.append("runtime_registry_missing_or_unreadable")
    expected_members = resolve_expected_members(sys.argv)
    ok, reasons = fm.verify_manifest(
        manifest, verify_sig=verify_sig,
        expected_members=expected_members, runtime_registry=runtime_registry,
    )
    reasons = pre_reasons + reasons
    ok = ok and not pre_reasons
    print("  signature + structure + registry ....... " + ("OK" if ok else "FAIL"))

    # Then re-derive every delivered artifact + karta hash from disk. Each member
    # MUST have EXACTLY one zip, one pdf, one plan present — missing OR duplicated
    # is a failure. The bundle is extracted once so we can also (a) re-derive the
    # karta hash and (b) run the bundle's OWN verify_identity.py to prove the
    # signed identity chain + file manifest are intact — the inner attestation is
    # re-checked, not taken on trust.
    for m in manifest.get("members", []):
        folder = m.get("folder", "?")
        z, p, pl, dupes = find_folder_files(folder)
        for label, count in dupes:
            reasons.append(f"{label}_not_exactly_one:{folder}:{count}")
        arts = m.get("artifacts") or {}
        for path, claimed, label in (
            (z, arts.get("bundle_zip_sha256"), "zip"),
            (p, arts.get("conformance_pdf_sha256"), "pdf"),
            (pl, arts.get("dev_plan_sha256"), "plan"),
        ):
            if not path:
                reasons.append(f"{label}_file_missing:{folder}")
                continue
            if not claimed or sha256_file(path) != claimed:
                reasons.append(f"{label}_hash_mismatch:{folder}")
        if not z:
            reasons.append(f"zip_file_missing:{folder}")
        else:
            try:
                with tempfile.TemporaryDirectory() as td:
                    with zipfile.ZipFile(z) as zf:
                        _safe_extractall(zf, td)
                    base = _bundle_root(td)
                    if not base:
                        reasons.append(f"identity_missing_in_zip:{folder}")
                    else:
                        kf = os.path.join(base, "karta.compiled.json")
                        if not os.path.exists(kf):
                            reasons.append(f"karta_missing_in_zip:{folder}")
                        elif sha256_file(kf) != m.get("karta_hash"):
                            reasons.append(f"karta_hash_mismatch:{folder}")
                        # DD review v2 (Peter #6): the member's SIGNED identity must
                        # name the same fleet UUID the manifest binds as
                        # fleet_identity_uuid — the explicit alias to the slug.
                        try:
                            _ident = json.load(open(os.path.join(base, "identity.json")))
                            _fid = str(((_ident.get("owner") or {}).get("fleet_id")) or "")
                            if _fid != str(manifest.get("fleet_identity_uuid") or ""):
                                reasons.append(f"identity_fleet_uuid_not_bound:{folder}")
                        except (OSError, ValueError):
                            reasons.append(f"identity_unreadable:{folder}")
                        vi = os.path.join(base, "verify_identity.py")
                        if not os.path.exists(vi):
                            reasons.append(f"verify_identity_missing:{folder}")
                        else:
                            r = subprocess.run([sys.executable, "-B", vi, base],
                                               capture_output=True, text=True)
                            if r.returncode != 0:
                                reasons.append(f"identity_signature_or_manifest_invalid:{folder}")
            except (zipfile.BadZipFile, OSError):
                reasons.append(f"zip_unreadable:{folder}")
        print(f"  {folder:32s} artifacts + karta + identity signature re-derived")

    # E2E binding (Peter DD): the recorded fleet_e2e_result.json must (a) re-hash
    # to its OWN result_sha256, (b) equal the sha256 bound in the SIGNED manifest,
    # and (c) report every case passed. A prose "N/N passed" is never trusted —
    # the run artifact is re-hashed and compared to the signed anchor.
    try:
        e2e = json.load(open(os.path.join(HERE, "fleet_e2e_result.json")))
    except (OSError, ValueError):
        e2e = None
    if not isinstance(e2e, dict):
        reasons.append("e2e_result_missing")
    else:
        body = {k: v for k, v in e2e.items() if k != "result_sha256"}
        recomputed = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if recomputed != e2e.get("result_sha256"):
            reasons.append("e2e_result_self_hash_mismatch")
        bound = (manifest.get("e2e_result") or {}).get("result_sha256")
        if not bound:
            reasons.append("e2e_result_not_bound_in_manifest")
        elif bound != recomputed:
            reasons.append("e2e_result_hash_not_bound_in_manifest")
        if not (e2e.get("total") and e2e.get("passed") == e2e.get("total") and e2e.get("failed") == 0):
            reasons.append("e2e_result_not_all_passed:%s/%s" % (e2e.get("passed"), e2e.get("total")))
    print("  fleet_e2e_result ...................... re-hashed + bound-to-manifest checked")

    print()
    if reasons:
        print("FLEET MANIFEST: FAIL")
        for r in sorted(set(reasons)):
            print("   -", r)
        sys.exit(1)
    print(f"FLEET MANIFEST: PASS — exactly {expected_members} agents bound, coordinator is a member, "
          f"one shared generator+root fingerprint, signature valid, runtime registry == manifest projection, "
          f"and every artifact + karta hash re-derived from the delivered files.")
    if pub == DEMO_FLEET_PUBKEY_HEX:
        print("TRUST LEVEL: INTERNAL CONSISTENCY — signed with the publicly derivable DEMO fleet key; EXTERNAL "
              "AUTHENTICITY: UNANCHORED until the production off-host key is used and this verifier's own digest "
              "has been checked against the out-of-band note (run verify_delivery_standalone.py first).")
    else:
        print("TRUST LEVEL: pin is not the DEMO key — external authenticity depends on how you obtained the pin and "
              "on having verified this tool's digest out-of-band first.")


if __name__ == "__main__":
    main()
