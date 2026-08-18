"""Regression tests for the OUTER (delivery-side) verifiers.

External DD review v2 (Peter, 2026-08-15) found that the delivered
00_Fleet/ed25519_verify.py was an OLD, unhardened copy — while the runtime copy
inside every bundle was hardened — and that both CLI verifiers took the signer
key from the very document they verified. Together that let a rewritten
manifest (identity-point 'signer' + trivial signature) print PASS.

These tests lock the class: (1) the outer ed25519 refuses identity-point,
small-order and non-canonical keys; (2) both verifiers refuse to run without an
external pin, refuse an embedded key that differs from the pin, and refuse the
forgery even when the attacker supplies his own key as the pin.

Run:  python -m pytest tools/fleet/test_outer_verifiers.py -q
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ed25519_verify import _p, ed25519_verify  # noqa: E402

IDENTITY_POINT = bytes([1]) + bytes(31)      # (0,1): on-curve, order 1
TRIVIAL_SIG = IDENTITY_POINT + bytes(32)     # R = identity, S = 0


# ── 1. the outer Ed25519 verifier itself ────────────────────────────────

def test_outer_ed25519_is_the_hardened_version():
    src = (HERE / "ed25519_verify.py").read_text()
    assert "_is_small_order" in src and "_is_identity" in src, \
        "tools/fleet/ed25519_verify.py must be the hardened (small-order/canonical) copy"


def test_identity_point_forgery_rejected_for_any_message():
    for msg in (b"a", b"b", b"", b"x" * 1000):
        assert ed25519_verify(IDENTITY_POINT, TRIVIAL_SIG, msg) is False


def test_non_canonical_pubkey_rejected():
    y_ge_p = (_p + 1).to_bytes(32, "little")
    assert ed25519_verify(y_ge_p, bytes(64), b"m") is False


def test_non_canonical_R_rejected():
    r_ge_p = (_p + 1).to_bytes(32, "little") + bytes(32)
    assert ed25519_verify(IDENTITY_POINT, r_ge_p, b"m") is False


# ── 2. the CLI verifiers: mandatory external pin ─────────────────────────

def _sign_lib():
    """Import the sign/pubkey primitives from delivery_manifest (pure python)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("dm", str(HERE / "delivery_manifest.py"))
    dm = importlib.util.module_from_spec(spec); spec.loader.exec_module(dm)
    return dm


@pytest.fixture
def mini_package(tmp_path):
    """A tiny package: 00_Fleet with a real, signed fleet_manifest.json (one
    file bound), the tools, and a DELIVERY_MANIFEST over it."""
    dm = _sign_lib()
    sign, pub, _ = dm._ed25519()
    root = tmp_path / "pkg"; fleet = root / "Fleet_Agents_2026-08" / "00_Fleet"; fleet.mkdir(parents=True)
    for f in ("ed25519_verify.py", "delivery_manifest.py", "verify_fleet_manifest.py", "fleet_manifest.py"):
        shutil.copy(HERE / f, fleet / f)
    (root / "doc.md").write_text("hello\n")
    seed = hashlib.sha256(b"test-seed").digest()
    # minimal fleet manifest with a valid signature (structure not exercised here)
    fm = {"manifest_version": "fleet_manifest/v1", "fleet_id": "t", "coordinator_agent_id": "c",
          "fleet_signal_version": "fleet_signal/v1", "k_policy": {}, "members": [], "e2e_result": {},
          "signer_pubkey_hex": pub(seed).hex(), "lease_pubkey_hex": "", "lease_epoch": 1, "registry_sha256": ""}
    body = json.dumps({k: v for k, v in fm.items()}, sort_keys=True, separators=(",", ":"), default=str).encode()
    fm["signature"] = {"alg": "ed25519", "sig": sign(seed, body).hex()}
    (fleet / "fleet_manifest.json").write_text(json.dumps(fm))
    m = dm.build(root, seed)
    (root / dm.MANIFEST_NAME).write_text(json.dumps(m, indent=2))
    return root, fleet, pub(seed).hex()


def _run(cwd, *args, env=None):
    e = dict(os.environ); e.pop("DELIVERY_TRUSTED_PUBKEY", None); e.pop("FLEET_TRUSTED_PUBKEY", None)
    if env: e.update(env)
    r = subprocess.run([sys.executable, *args], cwd=cwd, capture_output=True, text=True, env=e)
    return r.returncode, r.stdout + r.stderr


def test_delivery_verify_refuses_without_pin(mini_package):
    root, fleet, pin = mini_package
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root))
    assert rc == 2 and "REFUSED" in out and "no trust anchor" in out


def test_delivery_verify_passes_with_correct_pin(mini_package):
    root, fleet, pin = mini_package
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root), "--trusted-pubkey", pin)
    assert rc == 0 and "PASS" in out, out


def test_delivery_verify_env_pin_also_works(mini_package):
    root, fleet, pin = mini_package
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root), env={"DELIVERY_TRUSTED_PUBKEY": pin})
    assert rc == 0 and "PASS" in out, out


def test_delivery_forgery_refused_with_real_pin_and_with_attacker_pin(mini_package):
    """Peter's exact attack: rewrite a hash entry, set signer = identity point,
    signature = identity + S=0. Must FAIL with the real pin (key != pin) AND
    with the attacker's own key supplied as pin (hardened ed25519 rejects)."""
    root, fleet, pin = mini_package
    m = json.loads((root / "DELIVERY_MANIFEST.json").read_text())
    m["files"][0]["sha256"] = "00" * 32
    m["signer_pubkey_hex"] = IDENTITY_POINT.hex()
    m["signature"] = {"alg": "ed25519", "sig": TRIVIAL_SIG.hex()}
    (root / "DELIVERY_MANIFEST.json").write_text(json.dumps(m))
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root), "--trusted-pubkey", pin)
    assert rc == 1 and "signer_pubkey_does_not_match_trusted_pin" in out
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root), "--trusted-pubkey", IDENTITY_POINT.hex())
    assert rc == 1 and "bad_signature" in out


def test_fleet_verify_refuses_without_pin_and_rejects_pin_mismatch(mini_package):
    root, fleet, pin = mini_package
    rc, out = _run(fleet, "verify_fleet_manifest.py")
    assert rc == 2 and "REFUSED" in out
    rc, out = _run(fleet, "verify_fleet_manifest.py", "--trusted-pubkey", "22" * 32)
    assert rc == 1 and "does not match the trusted pin" in out


# ── 3. signed identity-UUID ↔ operational fleet-slug alias (Peter v2 #6) ────

def _minimal_manifest_for_alias(uuid_for_members, manifest_uuid):
    import fleet_manifest as fm
    m = {"manifest_version": fm.FLEET_MANIFEST_VERSION, "fleet_id": "cybersecurity-fleet-eihwaz",
         "coordinator_agent_id": "c", "fleet_signal_version": "fleet_signal/v1", "k_policy": {},
         "members": [{"agent_id": "c", "identity_fleet_uuid": uuid_for_members[0]},
                     {"agent_id": "s", "identity_fleet_uuid": uuid_for_members[1]}],
         "e2e_result": {}, "signer_pubkey_hex": "", "lease_pubkey_hex": "", "lease_epoch": 1,
         "registry_sha256": "", "signature": {"alg": "ed25519", "sig": "00"}}
    if manifest_uuid is not None:
        m["fleet_identity_uuid"] = manifest_uuid
    return m


def test_fleet_identity_uuid_alias_is_checked_per_member():
    import fleet_manifest as fm
    U = "cb307819-3c99-4e48-a83d-164ace3c6734"
    ok_sig = lambda body, sig: True  # isolate the alias check from signature/structure
    _, reasons = fm.verify_manifest(_minimal_manifest_for_alias([U, U], U), verify_sig=ok_sig)
    assert not [r for r in reasons if "fleet_identity_uuid" in r]
    _, reasons = fm.verify_manifest(_minimal_manifest_for_alias([U, "0" * 36], U), verify_sig=ok_sig)
    assert "fleet_identity_uuid_mismatch:s" in reasons
    _, reasons = fm.verify_manifest(_minimal_manifest_for_alias([U, U], None), verify_sig=ok_sig)
    assert "missing_fleet_identity_uuid" in reasons


def test_build_manifest_refuses_members_from_different_identity_fleets():
    import fleet_manifest as fm
    members = [{"agent_id": "c", "identity_fleet_uuid": "a" * 36, "karta_hash": "x", "artifacts": {},
                "generator_fingerprint": "g", "root_fingerprint": "r", "capability_scope": [], "doctrine_version": "d", "pubkey_hex": "p"},
               {"agent_id": "s", "identity_fleet_uuid": "b" * 36, "karta_hash": "x", "artifacts": {},
                "generator_fingerprint": "g", "root_fingerprint": "r", "capability_scope": [], "doctrine_version": "d", "pubkey_hex": "p"}]
    with pytest.raises(ValueError):
        fm.build_manifest(fleet_id="f", coordinator_agent_id="c", members=members,
                          fleet_signal_version="fleet_signal/v1", k_policy={}, sign=lambda b: "00",
                          signer_pubkey_hex="", lease_pubkey_hex="", lease_epoch=1, e2e_result={})


# ── 4. the OUT-OF-BAND standalone root verifier (DD review v3, P0-1) ────────
# The in-package delivery_manifest.py imports ed25519_verify.py from the same
# package it verifies: replace that file with an accept-all verifier, update its
# hash entry in DELIVERY_MANIFEST.json (no re-sign) → the in-package CLI prints
# PASS with the real pin. The standalone verifier imports nothing from the
# package and must FAIL on the same tree.

def _standalone():
    """The standalone verifier is delivered OUT-OF-BAND, so it may not sit next
    to this file when the suite runs from inside a delivered package. Look next
    to HERE first, then STANDALONE_VERIFIER=<path>; otherwise skip with a
    message that says exactly what to set."""
    cand = HERE / "verify_delivery_standalone.py"
    if cand.exists():
        return cand
    env = os.environ.get("STANDALONE_VERIFIER", "")
    if env and Path(env).exists():
        return Path(env)
    pytest.skip("verify_delivery_standalone.py is delivered out-of-band; set STANDALONE_VERIFIER=<path> to run this test")


def _tamper_inpackage_verifier(root, fleet):
    ev = fleet / "ed25519_verify.py"
    ev.write_text(ev.read_text() + "\n\ndef ed25519_verify(public_key, signature, message):\n    return True\n")
    mp = root / "DELIVERY_MANIFEST.json"; m = json.loads(mp.read_text())
    b = ev.read_bytes()
    for e in m["files"]:
        if e["path"].endswith("00_Fleet/ed25519_verify.py"):
            e["sha256"] = hashlib.sha256(b).hexdigest(); e["size"] = len(b)
    mp.write_text(json.dumps(m))


def test_standalone_refuses_without_pin_and_passes_with_pin(mini_package):
    root, fleet, pin = mini_package
    sa = _standalone()
    rc, out = _run(root, str(sa), str(root))
    assert rc == 2 and "REFUSED" in out
    rc, out = _run(root, str(sa), str(root), "--trusted-pubkey", pin)
    assert rc == 0 and "STANDALONE ROOT VERIFY: PASS" in out, out


def test_standalone_catches_the_circular_bootstrap_attack(mini_package):
    """Peter's P0-1 repro: in-package CLI PASSes, standalone FAILs (bad_signature)."""
    root, fleet, pin = mini_package
    _tamper_inpackage_verifier(root, fleet)
    rc_in, out_in = _run(fleet, "delivery_manifest.py", "verify", str(root), "--trusted-pubkey", pin)
    assert rc_in == 0 and "PASS" in out_in, "precondition: the in-package CLI is fooled (that is the finding)"
    rc, out = _run(root, str(_standalone()), str(root), "--trusted-pubkey", pin)
    assert rc == 1 and "bad_signature" in out, out


def test_standalone_imports_nothing_from_the_package():
    src = _standalone().read_text()
    imports = {l.split()[1].split(".")[0] for l in src.splitlines() if l.startswith(("import ", "from "))}
    assert imports <= {"hashlib", "json", "os", "shutil", "sys", "tempfile", "zipfile", "pathlib", "typing"}, imports
    assert "sys.path" not in src and "importlib" not in src


def test_demo_pin_is_labelled_internal_consistency(mini_package):
    root, fleet, pin = mini_package
    # the mini package is signed with a TEST seed, not the DEMO seed → non-DEMO label
    rc, out = _run(fleet, "delivery_manifest.py", "verify", str(root), "--trusted-pubkey", pin)
    assert rc == 0 and "TRUST LEVEL:" in out
    dm = _sign_lib()
    assert dm.trust_level(dm.DEMO_PUBKEY_HEX).startswith("TRUST LEVEL: INTERNAL CONSISTENCY")
    _, pub, _ = dm._ed25519()
    assert pub(dm.DEMO_SEED).hex() == dm.DEMO_PUBKEY_HEX, "DEMO_PUBKEY_HEX constant must equal pub(DEMO_SEED)"



# ── 5. DD review v4 P0: strict inventory — cache/symlink/unlisted → FAIL ────

def test_standalone_fails_on_unlisted_pyc(mini_package):
    """External DD v4 repro: drop a valid but UNLISTED .pyc under 00_Fleet/__pycache__
    without touching any source or manifest. The strict verifier must FAIL
    (the interpreter would load exactly such a file)."""
    root, fleet, pin = mini_package
    import py_compile
    cache = fleet / "__pycache__"; cache.mkdir(exist_ok=True)
    pyc = cache / "ed25519_verify.cpython-312.pyc"
    py_compile.compile(str(fleet / "ed25519_verify.py"), cfile=str(pyc))
    rc, out = _run(root, str(_standalone()), str(root), "--trusted-pubkey", pin)
    assert rc == 1 and ("unlisted:" in out and "__pycache__" in out), out


def test_standalone_fails_on_symlink(mini_package):
    root, fleet, pin = mini_package
    try:
        (root / "sneaky.md").symlink_to(root / "doc.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this filesystem")
    rc, out = _run(root, str(_standalone()), str(root), "--trusted-pubkey", pin)
    assert rc == 1 and "symlink:sneaky.md" in out, out


def test_standalone_fails_on_unlisted_plain_file(mini_package):
    root, fleet, pin = mini_package
    (fleet / "sitecustomize.py").write_text("# unlisted\n")
    rc, out = _run(root, str(_standalone()), str(root), "--trusted-pubkey", pin)
    assert rc == 1 and "unlisted:" in out and "sitecustomize.py" in out, out


def test_standalone_zip_mode_checks_hash_then_verifies_fresh(mini_package, tmp_path):
    """--zip mode: verify the package zip's own sha256, extract to a fresh temp
    dir, verify that. Wrong --sha256 → refuse before extraction."""
    import hashlib as _h, zipfile as _z
    root, fleet, pin = mini_package
    z = tmp_path / "pkg.zip"
    with _z.ZipFile(z, "w") as zf:
        for base, _dirs, names in os.walk(root):
            for n in names:
                fp = Path(base) / n
                zf.write(fp, "pkg/" + str(fp.relative_to(root)))
    sha = _h.sha256(z.read_bytes()).hexdigest()
    rc, out = _run(tmp_path, str(_standalone()), "--zip", str(z), "--sha256", sha, "--trusted-pubkey", pin)
    assert rc == 0 and "STANDALONE ROOT VERIFY: PASS" in out and "matches the expected sha256" in out, out
    rc, out = _run(tmp_path, str(_standalone()), "--zip", str(z), "--sha256", "00" * 32, "--trusted-pubkey", pin)
    assert rc == 1 and "does not match --sha256" in out, out


def test_standalone_zip_mode_refuses_duplicate_central_directory_names(mini_package, tmp_path):
    """P2 (external review round 5): two entries with the same name — extractall
    keeps the last, so a benign+malicious pair of a listed path could slip
    through. The --zip mode must refuse."""
    import hashlib as _h, zipfile as _z
    root, fleet, pin = mini_package
    z = tmp_path / "dup.zip"
    with _z.ZipFile(z, "w") as zf:
        for base, _dirs, names in os.walk(root):
            for n in names:
                fp = Path(base) / n
                zf.write(fp, "pkg/" + str(fp.relative_to(root)))
        zf.writestr("pkg/doc.md", "malicious replacement\n")   # duplicate name
    sha = _h.sha256(z.read_bytes()).hexdigest()
    rc, out = _run(tmp_path, str(_standalone()), "--zip", str(z), "--sha256", sha, "--trusted-pubkey", pin)
    assert rc == 1 and "duplicate name in zip central directory" in out, out


def test_standalone_zip_mode_refuses_normalized_alias_entries(mini_package, tmp_path):
    """Round 6 (external review): 'x' and './x' are different raw names but the
    SAME extraction target after normalisation — the raw-name duplicate check
    missed them. The canonical-target check must refuse."""
    import hashlib as _h, zipfile as _z
    root, fleet, pin = mini_package
    z = tmp_path / "alias.zip"
    with _z.ZipFile(z, "w") as zf:
        for base, _dirs, names in os.walk(root):
            for n in names:
                fp = Path(base) / n
                zf.write(fp, "pkg/" + str(fp.relative_to(root)))
        zf.writestr("./pkg/doc.md", "malicious alias\n")   # normalises to pkg/doc.md
    sha = _h.sha256(z.read_bytes()).hexdigest()
    rc, out = _run(tmp_path, str(_standalone()), "--zip", str(z), "--sha256", sha, "--trusted-pubkey", pin)
    assert rc == 1 and "normalise to the same extraction target" in out, out
