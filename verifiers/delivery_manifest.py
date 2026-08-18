#!/usr/bin/env python3
"""delivery_manifest — a signed ROOT manifest over EVERY file in the DD package.

External DD reviews (2026-08-15, Codex + Peter): the fleet manifest binds the
fleet artifacts, but the SOC documents, the SOC repo snapshot and the verifier
tools themselves were not bound by any signature — a reviewer could not tell
whether the package they held was the package we assembled. This closes that:

  build  <package_root> [--seed-hex <64hex>]   -> writes DELIVERY_MANIFEST.json (signed)
  verify <package_root> --trusted-pubkey <hex> -> re-hashes every file, checks the signature against the
                                                  EXTERNAL pin (mandatory; env DELIVERY_TRUSTED_PUBKEY also accepted)

The manifest lists every regular file under the package root (path, size,
sha256) except itself, sorted, plus the fleet manifest's own signature digest so
the two anchors are cross-bound. Ed25519 over the canonical JSON body. The
signer key is DEMO by default (deterministic, receiver-reproducible — same
posture as the fleet manifest); production replaces it with an off-host key via
--seed-hex / DELIVERY_SIGNING_SEED. Pure stdlib + the shipped ed25519 module.
"""
import hashlib
import json
import os
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True  # never leave a __pycache__ behind in a delivered tree


def _load_source(name: str, path):
    """Load a sibling module FROM SOURCE — compile + exec — bypassing any
    __pycache__/*.pyc the interpreter would otherwise prefer (external DD review
    v4, P0: an unlisted but valid .pyc next to the source is what `import` loads)."""
    src = open(path, "rb").read()
    mod = types.ModuleType(name); mod.__file__ = str(path)
    exec(compile(src, str(path), "exec"), mod.__dict__)
    return mod

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MANIFEST_NAME = "DELIVERY_MANIFEST.json"
VERSION = "delivery_manifest/v1"
DEMO_SEED = hashlib.sha256(b"DEMO-DELIVERY-MANIFEST-KEY-2026-08-15").digest()
# Build/test caches are never release content (a receiver running pytest inside
# the package must not turn the package into a "modified" one); .git for safety.
# STRICT inventory (DD review v4 P0): no directory or file is skipped except
# the manifest itself; symlinks are failures. Build over a CLEAN tree.
SKIP_DIRS: set = set()
SKIP_FILES = {MANIFEST_NAME}
# Public key of the DEMO seed above. When the pin equals it, the verifier says so:
# the result is INTERNAL CONSISTENCY, not external authenticity (DD review v3).
DEMO_PUBKEY_HEX = "6813a7c3574cd3ccbdf2e55000d605352351f14c5e866cef6b1109d74d61dbe8"


def trust_level(pin_hex: str) -> str:
    if str(pin_hex).lower() == DEMO_PUBKEY_HEX:
        return ("TRUST LEVEL: INTERNAL CONSISTENCY — signed with the publicly derivable DEMO key; "
                "EXTERNAL AUTHENTICITY: UNANCHORED until the production off-host key + the out-of-band "
                "standalone verifier (verify_delivery_standalone.py) are used.")
    return ("TRUST LEVEL: pin is not the DEMO key — external authenticity depends on how you obtained the pin "
            "and on running the out-of-band standalone verifier first.")


def _ed25519():
    """Sign + pubkey come from a delivered bundle's fleet_trust (pure python)."""
    import importlib.util
    # ed25519_verify.py ships next to this tool (verify only); sign needs fleet_trust.
    for cand in [HERE / "ed25519_sign_lib.py"]:
        if cand.exists():
            spec = importlib.util.spec_from_file_location("edsign", str(cand))
            m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
            return m.ed25519_sign, m.ed25519_public_key, m.ed25519_verify
    ev = _load_source("ed25519_verify", HERE / "ed25519_verify.py")
    ed25519_verify = ev.ed25519_verify
    # derive sign/pubkey from the same primitives (RFC 8032) using the verify
    # module's internals; the shipped module is verify-only, so the point
    # encoder (RFC 8032 §5.1.2: y little-endian, x parity in the top bit) lives here.
    def encodepoint(P) -> bytes:
        (x, y, z, t) = P
        zi = ev._inv(z); x = (x * zi) % ev._p; y = (y * zi) % ev._p
        return (y | ((x & 1) << 255)).to_bytes(32, "little")
    def public_key(seed: bytes) -> bytes:
        h = ev._H(seed); a = int.from_bytes(h[:32], "little"); a &= (1 << 254) - 8; a |= 1 << 254
        return encodepoint(ev._scalarmult(ev._B, a))
    def sign(seed: bytes, msg: bytes) -> bytes:
        h = ev._H(seed); a = int.from_bytes(h[:32], "little"); a &= (1 << 254) - 8; a |= 1 << 254
        prefix = h[32:]; A = encodepoint(ev._scalarmult(ev._B, a))
        r = int.from_bytes(ev._H(prefix + msg), "little") % ev._L
        R = encodepoint(ev._scalarmult(ev._B, r))
        k = int.from_bytes(ev._H(R + A + msg), "little") % ev._L
        S = (r + k * a) % ev._L
        return R + S.to_bytes(32, "little")
    return sign, public_key, ed25519_verify


_SYMLINKS: list = []


def _walk(root: Path):
    _SYMLINKS.clear()
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for d in list(dirs):
            if (Path(base) / d).is_symlink():
                _SYMLINKS.append((Path(base) / d).relative_to(root).as_posix() + "/"); dirs.remove(d)
        for f in sorted(files):
            if f in SKIP_FILES:
                continue
            p = Path(base) / f
            if p.is_symlink():
                _SYMLINKS.append(p.relative_to(root).as_posix()); continue
            if not p.is_file():
                _SYMLINKS.append(p.relative_to(root).as_posix() + " (not a regular file)"); continue
            yield p


def _entries(root: Path):
    out = []
    for p in _walk(root):
        b = p.read_bytes()
        out.append({"path": p.relative_to(root).as_posix(), "size": len(b),
                    "sha256": hashlib.sha256(b).hexdigest()})
    return out


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build(root: Path, seed: bytes) -> dict:
    sign, pub, _ = _ed25519()
    entries = _entries(root)
    if _SYMLINKS:
        raise SystemExit("delivery_manifest build: refusing — symlinks/non-regular entries in tree: %r" % _SYMLINKS[:5])
    fm_path = next((p for p in _walk(root) if p.name == "fleet_manifest.json"), None)
    fleet_sig = None
    if fm_path:
        try:
            fleet_sig = (json.loads(fm_path.read_text()).get("signature") or {}).get("sig")
        except Exception:
            fleet_sig = None
    body = {
        "manifest_version": VERSION,
        "package": root.name,
        "file_count": len(entries),
        "files": entries,
        "fleet_manifest_signature_sha256": hashlib.sha256((fleet_sig or "").encode()).hexdigest() if fleet_sig else None,
        "signer_pubkey_hex": pub(seed).hex(),
        "_note": ("Signed ROOT manifest over every delivered file (path, size, sha256), cross-bound to the fleet "
                  "manifest signature. DEMO signer by default — production re-signs off-host and supplies the "
                  "public key + this verifier's digest on a separate channel."),
    }
    body["signature"] = {"alg": "ed25519", "sig": sign(seed, _canonical({k: v for k, v in body.items() if k != "signature"})).hex()}
    return body


def verify(root: Path, trusted_pubkey_hex: str):
    """trusted_pubkey_hex is the MANDATORY external trust anchor (DD P0, external
    review v2): the signer key embedded in DELIVERY_MANIFEST.json is never used
    as the anchor — an attacker rewriting the manifest rewrites key + signature
    together. The embedded key must EQUAL the pin, then the signature is checked
    against the PIN."""
    _, _, ver = _ed25519()
    m = json.loads((root / MANIFEST_NAME).read_text())
    reasons = []
    pin = str(trusted_pubkey_hex or "").strip().lower()
    if str(m.get("signer_pubkey_hex", "")).lower() != pin:
        return ["signer_pubkey_does_not_match_trusted_pin"]
    body = {k: v for k, v in m.items() if k != "signature"}
    try:
        ok = ver(bytes.fromhex(pin), bytes.fromhex(m["signature"]["sig"]), _canonical(body))
    except Exception:
        ok = False
    if not ok:
        reasons.append("bad_signature")
    listed = {e["path"]: e for e in m.get("files", [])}
    on_disk = {e["path"]: e for e in _entries(root)}
    for sl in _SYMLINKS:
        reasons.append("symlink:" + sl)
    for p, e in listed.items():
        d = on_disk.get(p)
        if d is None:
            reasons.append("missing:" + p)
        elif d["sha256"] != e["sha256"] or d["size"] != e["size"]:
            reasons.append("modified:" + p)
    for p in on_disk:
        if p not in listed:
            reasons.append("unlisted:" + p)
    if m.get("file_count") != len(listed):
        reasons.append("file_count_mismatch")
    fm_path = next((p for p in _walk(root) if p.name == "fleet_manifest.json"), None)
    if fm_path and m.get("fleet_manifest_signature_sha256"):
        sig = (json.loads(fm_path.read_text()).get("signature") or {}).get("sig") or ""
        if hashlib.sha256(sig.encode()).hexdigest() != m["fleet_manifest_signature_sha256"]:
            reasons.append("fleet_manifest_signature_not_bound")
    return reasons


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("build", "verify"):
        raise SystemExit(__doc__)
    root = Path(sys.argv[2]).resolve()
    if sys.argv[1] == "build":
        seed_hex = os.environ.get("DELIVERY_SIGNING_SEED", "")
        if "--seed-hex" in sys.argv:
            seed_hex = sys.argv[sys.argv.index("--seed-hex") + 1]
        seed = bytes.fromhex(seed_hex) if seed_hex else DEMO_SEED
        m = build(root, seed)
        (root / MANIFEST_NAME).write_text(json.dumps(m, indent=2))
        print(f"DELIVERY_MANIFEST: {m['file_count']} files bound | signer {m['signer_pubkey_hex'][:16]}… | "
              f"{'DEMO key' if seed == DEMO_SEED else 'PRODUCTION key'}")
        print(f"TRUSTED PIN (give to the receiver on a separate channel): {m['signer_pubkey_hex']}")
    else:
        pin = None
        if "--trusted-pubkey" in sys.argv:
            i = sys.argv.index("--trusted-pubkey"); pin = sys.argv[i + 1] if i + 1 < len(sys.argv) else None
        pin = (pin or os.environ.get("DELIVERY_TRUSTED_PUBKEY", "")).strip().lower()
        if not pin:
            print("DELIVERY MANIFEST: REFUSED — no trust anchor. Supply the signer public key out-of-band: "
                  "--trusted-pubkey <64-hex> (or DELIVERY_TRUSTED_PUBKEY=<64-hex>). The key embedded in the "
                  "manifest is NOT used as an anchor."); sys.exit(2)
        try:
            if len(bytes.fromhex(pin)) != 32: raise ValueError
        except ValueError:
            print("DELIVERY MANIFEST: REFUSED — trusted pubkey must be 32 bytes / 64 hex chars."); sys.exit(2)
        reasons = verify(root, pin)
        if reasons:
            print("DELIVERY MANIFEST: FAIL"); [print("   -", r) for r in sorted(reasons)]; sys.exit(1)
        m = json.loads((root / MANIFEST_NAME).read_text())
        print(f"DELIVERY MANIFEST: PASS — {m['file_count']} files re-hashed, signature valid, fleet manifest cross-bound.")
        print(trust_level(pin))


if __name__ == "__main__":
    main()
