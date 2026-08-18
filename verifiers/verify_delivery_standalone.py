#!/usr/bin/env python3
"""verify_delivery_standalone — INDEPENDENT root verifier for a HexaBox DD package.

This file is delivered on a SEPARATE trusted channel (never inside the package it
verifies) together with its own sha256. It imports NOTHING from the package: the
hardened Ed25519 verifier is embedded below, canonicalisation is embedded, and
the only inputs are the package root, the manifest inside it, and the pin you
received out-of-band. Run it FIRST, from a clean directory, before trusting or
executing any tool that shipped inside the package (those tools are themselves
files bound by the root manifest — this verifier is what anchors them).

    python3 verify_delivery_standalone.py --zip <package.zip> --sha256 <zip-sha256> --trusted-pubkey <64-hex>
    python3 verify_delivery_standalone.py <fresh_package_root> --trusted-pubkey <64-hex>
    (or DELIVERY_TRUSTED_PUBKEY=<64-hex>)

Fail-closed:
  * refuses to run without an external pin (exit 2);
  * the manifest's embedded signer key must EQUAL the pin (else exit 1);
  * Ed25519 signature over the canonical manifest body is checked against the PIN
    with canonical-y bounds and small-order/identity-point rejection;
  * STRICT inventory: every entry under the root except the manifest itself is
    re-hashed — including __pycache__/*.pyc, .pytest_cache, __MACOSX, .DS_Store,
    .pth, sitecustomize.py, .git — a modified, missing or UNLISTED entry is a
    failure and every symlink is a failure (DD review v4 P0: an unlisted valid
    .pyc next to a source file is what the interpreter would execute);
  * with --zip <package.zip> [--sha256 <hex>] the package zip's own digest is
    checked FIRST and the tree is extracted into a fresh temporary directory —
    verify fresh extractions, never a tree you have run tests in;
  * file_count must match; no duplicate paths;
  * the fleet manifest signature is cross-bound (sha256 of its sig field);
  * finally it PRINTS the sha256 of every in-package verifier/tool so you can
    compare them with the digests in the reviewer note before running them.

External DD review v3 (2026-08-15) finding P0-1: a verifier loaded from the package
it verifies is a circular bootstrap — this file closes it.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True  # this verifier never leaves a cache behind

# ─────────────────────────────── embedded hardened Ed25519 (verify only) ──
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


# ─────────────────────────────── root manifest verification ───────────────
MANIFEST_NAME = "DELIVERY_MANIFEST.json"
DEMO_PUBKEY_HEX = "6813a7c3574cd3ccbdf2e55000d605352351f14c5e866cef6b1109d74d61dbe8"
TOOLS_TO_DIGEST = ("delivery_manifest.py", "ed25519_verify.py", "verify_fleet_manifest.py",
                   "run_fleet_e2e.py", "fleet_manifest.py", "test_outer_verifiers.py")


def _inventory(root: Path):
    """STRICT inventory (external DD review v4, P0): NOTHING is skipped. Every
    directory entry under the root — including __pycache__/*.pyc, .pytest_cache,
    __MACOSX, .DS_Store, .pth, sitecustomize.py, .git — is either listed in the
    manifest or a FAILURE, and every symlink is a FAILURE. There is no exception
    list because an exception list is exactly where an unlisted, executable file
    hides (a valid .pyc next to a source file is what the interpreter loads).
    Verify a FRESH extraction; if you have run tests inside the tree, re-extract
    before verifying again — do not expect the verifier to forgive caches."""
    files, symlinks, others = {}, [], []
    for base, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        for d in list(dirs):
            dp = Path(base) / d
            if dp.is_symlink():
                symlinks.append(dp.relative_to(root).as_posix() + "/"); dirs.remove(d)
        for f in sorted(names):
            p = Path(base) / f
            rel = p.relative_to(root).as_posix()
            if rel == MANIFEST_NAME:
                continue
            if p.is_symlink():
                symlinks.append(rel); continue
            if not p.is_file():
                others.append(rel); continue
            b = p.read_bytes()
            files[rel] = {"size": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    return files, symlinks, others


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def main() -> int:
    args = [a for a in sys.argv[1:]]
    if not args:
        print(__doc__); return 2
    pin = None
    if "--trusted-pubkey" in args:
        i = args.index("--trusted-pubkey"); pin = args[i + 1] if i + 1 < len(args) else None
    pin = (pin or os.environ.get("DELIVERY_TRUSTED_PUBKEY", "")).strip().lower()
    if not pin:
        print("STANDALONE ROOT VERIFY: REFUSED — no trust anchor. Supply the delivery signer public key "
              "out-of-band: --trusted-pubkey <64-hex> (or DELIVERY_TRUSTED_PUBKEY). The key embedded in the "
              "manifest is NOT used as an anchor."); return 2
    try:
        if len(bytes.fromhex(pin)) != 32:
            raise ValueError
    except ValueError:
        print("STANDALONE ROOT VERIFY: REFUSED — pin must be 32 bytes / 64 hex chars."); return 2

    tmp = None
    if "--zip" in args:
        # Mode 2 (DD review v4): verify the PACKAGE ZIP's own sha256 first, then
        # extract it into a FRESH temporary directory and verify that — never a
        # tree that has already been used.
        i = args.index("--zip"); zpath = Path(args[i + 1]).resolve() if i + 1 < len(args) else None
        exp = None
        if "--sha256" in args:
            j = args.index("--sha256"); exp = (args[j + 1] if j + 1 < len(args) else "").strip().lower()
        if not zpath or not zpath.is_file():
            print("STANDALONE ROOT VERIFY: REFUSED — --zip needs a path to the package zip."); return 2
        actual = hashlib.sha256(zpath.read_bytes()).hexdigest()
        print("package zip sha256:", actual)
        if exp:
            if actual != exp:
                print("STANDALONE ROOT VERIFY: FAIL — package zip sha256 does not match --sha256 (expected %s…). "
                      "Do not extract it." % exp[:16]); return 1
            print("  matches the expected sha256 received out-of-band")
        else:
            print("  (no --sha256 given: compare this value with the one received out-of-band before trusting the result)")
        tmp = tempfile.mkdtemp(prefix="dd_verify_")
        with zipfile.ZipFile(zpath) as zf:
            dest_real = os.path.realpath(tmp)
            seen_names = set()
            seen_targets = set()
            for info in zf.infolist():
                # P2 hardening (external review, round 5): a zip central directory may
                # carry the SAME name twice — extractall keeps the LAST entry, so a
                # duplicate lets an attacker ship one benign and one malicious copy
                # of a listed path. Refuse duplicates outright.
                if info.filename in seen_names:
                    print("STANDALONE ROOT VERIFY: FAIL — duplicate name in zip central directory: %r" % info.filename); return 1
                seen_names.add(info.filename)
                # Round 6: raw-name comparison misses ALIASES that extract to the
                # same destination — 'x' vs './x' vs 'a/../x' normalise to one
                # target (and case-insensitive filesystems collapse 'X' vs 'x').
                # Compare the CANONICAL extraction target, case-folded, so two
                # entries can never write the same file under any receiver OS.
                if not info.filename.endswith("/"):
                    canon = os.path.normpath(info.filename).casefold()
                    if canon in seen_targets:
                        print("STANDALONE ROOT VERIFY: FAIL — two zip entries normalise to the same extraction target: %r" % info.filename); return 1
                    seen_targets.add(canon)
                target = os.path.realpath(os.path.join(tmp, info.filename))
                if not (target == dest_real or target.startswith(dest_real + os.sep)):
                    print("STANDALONE ROOT VERIFY: FAIL — zip entry escapes extraction dir: %r" % info.filename); return 1
                # symlink entries in a zip carry mode 0o120000 in external_attr
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    print("STANDALONE ROOT VERIFY: FAIL — zip contains a symlink entry: %r" % info.filename); return 1
            zf.extractall(tmp)
        entries = [p for p in Path(tmp).iterdir()]
        root = entries[0] if len(entries) == 1 and entries[0].is_dir() and not (Path(tmp) / MANIFEST_NAME).exists() else Path(tmp)
        print("fresh extraction:", root)
    else:
        if args[0].startswith("--"):
            print(__doc__); return 2
        root = Path(args[0]).resolve()
    try:
        return _verify_tree(root, pin)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def _verify_tree(root: Path, pin: str) -> int:
    mp = root / MANIFEST_NAME
    if not mp.is_file():
        print("STANDALONE ROOT VERIFY: FAIL — %s missing at package root" % MANIFEST_NAME); return 1
    try:
        m = json.loads(mp.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        print("STANDALONE ROOT VERIFY: FAIL — manifest unreadable: %r" % e); return 1

    reasons = []
    if str(m.get("signer_pubkey_hex", "")).lower() != pin:
        print("STANDALONE ROOT VERIFY: FAIL — signer_pubkey_hex does not match the trusted pin (embedded %s… vs "
              "pinned %s…). Manifest refused." % (str(m.get("signer_pubkey_hex", ""))[:16], pin[:16])); return 1
    body = {k: v for k, v in m.items() if k != "signature"}
    try:
        ok = ed25519_verify(bytes.fromhex(pin), bytes.fromhex((m.get("signature") or {}).get("sig", "")), _canonical(body))
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        reasons.append("bad_signature")
    listed = {e["path"]: e for e in m.get("files", [])}
    if len(listed) != len(m.get("files", [])):
        reasons.append("duplicate_paths_in_manifest")
    on_disk, symlinks, others = _inventory(root)
    for sl in symlinks:
        reasons.append("symlink:" + sl)
    for o in others:
        reasons.append("not_a_regular_file:" + o)
    for path, e in listed.items():
        d = on_disk.get(path)
        if d is None:
            reasons.append("missing:" + path)
        elif d["sha256"] != e.get("sha256") or d["size"] != e.get("size"):
            reasons.append("modified:" + path)
    for path in on_disk:
        if path not in listed:
            reasons.append("unlisted:" + path)
    if m.get("file_count") != len(listed):
        reasons.append("file_count_mismatch")
    fm_path = next((root / p for p in on_disk if os.path.basename(p) == "fleet_manifest.json"), None)
    if fm_path is None:
        reasons.append("fleet_manifest_missing")
    elif m.get("fleet_manifest_signature_sha256"):
        try:
            sig = (json.loads(fm_path.read_text()).get("signature") or {}).get("sig") or ""
        except Exception:  # noqa: BLE001
            sig = ""
        if hashlib.sha256(sig.encode()).hexdigest() != m["fleet_manifest_signature_sha256"]:
            reasons.append("fleet_manifest_signature_not_bound")
    else:
        reasons.append("fleet_manifest_signature_not_bound_in_manifest")

    print("in-package tool digests (compare with the reviewer note BEFORE running them):")
    for path in sorted(on_disk):
        if os.path.basename(path) in TOOLS_TO_DIGEST:
            print("  %s  %s" % (on_disk[path]["sha256"], path))
    print()
    if reasons:
        print("STANDALONE ROOT VERIFY: FAIL")
        for r in sorted(set(reasons)):
            print("   -", r)
        return 1
    print("STANDALONE ROOT VERIFY: PASS — %d files re-hashed, signature valid against the external pin, "
          "fleet manifest cross-bound. (Verifier code: this file, delivered out-of-band; nothing imported "
          "from the package.)" % len(listed))
    if pin == DEMO_PUBKEY_HEX:
        print("TRUST LEVEL: INTERNAL CONSISTENCY — the pin is the publicly derivable DEMO delivery key; "
              "EXTERNAL AUTHENTICITY: UNANCHORED until the package is re-signed with the production off-host key.")
    else:
        print("TRUST LEVEL: non-DEMO pin — external authenticity is as strong as the channel that delivered "
              "the pin and this file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
