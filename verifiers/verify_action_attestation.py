#!/usr/bin/env python3
"""Standalone verifier for a HexaID action attestation (hexabox.action_attestation/v1).

A receiving system (an EDR/XDR platform, an MSP console, an auditor) got a provider call from a
HexaBox-governed agent carrying the header ``X-HexaID-Attestation``. This tool answers, OFFLINE and
with no HexaBox software or network access, whether that call was genuinely sanctioned:

  python3 verify_action_attestation.py --token '<header value>' --trusted-pubkey '<base64 from TRUST.md>'
          [--audience api.example.com] [--idempotency-key <64-hex>] [--digest <64-hex>] [--now <iso8601>]

The trusted public key is the 'Action attestation signer' pin on the HexaBox trust channel
(github.com/Reaktlive/hexabox-trust → TRUST.md). Obtain it from THERE, never from the token.
Exit 0 and a JSON verdict with "valid": true on success; exit 1 otherwise, with every reason.
Pure stdlib, RFC 8032 Ed25519 — the same hardened verifier family as verify_identity.py.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, sys
from datetime import datetime, timedelta, timezone

SCHEMA = "hexabox.action_attestation/v1"
ALG = "ed25519"

# ---------- minimal Ed25519 verify (RFC 8032, pure Python, hardened) ----------
_p = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)
def _H(m): return hashlib.sha512(m).digest()
def _inv(x): return pow(x, _p - 2, _p)
def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1); x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0: x = (x * _I) % _p
    if x % 2 != 0: x = _p - x
    return x
_By = (4 * _inv(5)) % _p; _Bx = _xrecover(_By); _B = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)
def _add(P, Q):
    (x1, y1, z1, t1) = P; (x2, y2, z2, t2) = Q
    a = ((y1 - x1) * (y2 - x2)) % _p; b = ((y1 + x1) * (y2 + x2)) % _p
    c = (t1 * 2 * _d * t2) % _p; dd = (z1 * 2 * z2) % _p
    e = b - a; f = dd - c; g = dd + c; h = b + a
    return ((e * f) % _p, (g * h) % _p, (f * g) % _p, (e * h) % _p)
def _mul(P, e):
    if e == 0: return (0, 1, 1, 0)
    Q = _mul(P, e // 2); Q = _add(Q, Q)
    if e & 1: Q = _add(Q, P)
    return Q
def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1); x = _xrecover(y)
    if x & 1 != (s[31] >> 7) & 1: x = _p - x
    return (x, y, 1, (x * y) % _p)
def _oncurve(P):
    (x, y, z, t) = P
    return z % _p != 0 and (x * y) % _p == (z * t) % _p and (y * y - x * x - z * z - _d * t * t) % _p == 0
def _small_order(P):
    (x, y, z, t) = _mul(P, 8); return x % _p == 0 and (y - z) % _p == 0
def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if len(signature) != 64 or len(public_key) != 32: return False
    if (int.from_bytes(signature[:32], "little") & ((1 << 255) - 1)) >= _p: return False
    if (int.from_bytes(public_key, "little") & ((1 << 255) - 1)) >= _p: return False
    try: R = _decodepoint(signature[:32]); A = _decodepoint(public_key)
    except Exception: return False
    if not (_oncurve(R) and _oncurve(A)) or _small_order(A): return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L: return False
    h = int.from_bytes(_H(signature[:32] + public_key + message), "little") % _L
    R1 = _mul(_B, S); R2 = _add(R, _mul(A, h))
    (x1, y1, z1, _) = R1; (x2, y2, z2, _) = R2
    return (x1 * z2 - x2 * z1) % _p == 0 and (y1 * z2 - y2 * z1) % _p == 0

# ---------- token ----------
def _unb64url(s): s = str(s).strip(); return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
def decode(token):
    parts = str(token).strip().split(".")
    if len(parts) != 2 or not parts[0] or not parts[1]: raise ValueError("token must be <payload>.<signature>")
    pb = _unb64url(parts[0]); sig = _unb64url(parts[1]); p = json.loads(pb.decode("utf-8"))
    if not isinstance(p, dict): raise ValueError("payload must be a JSON object")
    return pb, p, sig
def _ts(v): return datetime.fromisoformat(str(v).replace("Z", "+00:00"))

def verify(token, *, trusted_pubkey_b64, now=None, expected_audience=None, expected_idempotency_key=None, expected_digest=None):
    """Mirrors runtime/fleet_api/action_attestation.verify — the normative check list in the spec."""
    reasons = []; now = now or datetime.now(timezone.utc)
    try: pb, p, sig = decode(token)
    except Exception as exc: return {"valid": False, "reasons": ["malformed:%s" % exc], "payload": None}
    if p.get("schema") != SCHEMA: reasons.append("bad_schema:%s" % p.get("schema"))
    if p.get("alg") != ALG: reasons.append("bad_alg:%s" % p.get("alg"))
    try: trusted = base64.b64decode(str(trusted_pubkey_b64))
    except Exception: trusted = b""
    if len(trusted) != 32: reasons.append("trusted_pubkey_invalid")
    else:
        if not ed25519_verify(trusted, sig, pb): reasons.append("bad_signature")
        if (p.get("signer") or {}).get("pubkey_b64") != base64.b64encode(trusted).decode("ascii"): reasons.append("signer_not_pinned")
    try:
        if _ts(p.get("expires_at")) <= now: reasons.append("expired")
        if _ts(p.get("issued_at")) > now + timedelta(seconds=60): reasons.append("issued_in_future")
    except Exception: reasons.append("bad_timestamps")
    if expected_audience is not None and p.get("audience") != expected_audience: reasons.append("audience_mismatch")
    if expected_idempotency_key is not None and p.get("idempotency_key") != expected_idempotency_key: reasons.append("idempotency_key_mismatch")
    if expected_digest is not None and (p.get("command") or {}).get("digest") != expected_digest: reasons.append("digest_mismatch")
    appr = p.get("approval") or {}; approvers = appr.get("approvers")
    if appr.get("status") != "approved" or not isinstance(approvers, list) or not approvers: reasons.append("no_approvals_attested")
    return {"valid": not reasons, "reasons": reasons, "payload": p,
            "approvers": len(approvers) if isinstance(approvers, list) else 0, "signer_id": (p.get("signer") or {}).get("id")}

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--token", help="the X-HexaID-Attestation header value"); ap.add_argument("--token-file", help="file holding the header value")
    ap.add_argument("--trusted-pubkey", required=True, help="base64 Ed25519 public key pinned on hexabox-trust TRUST.md")
    ap.add_argument("--audience", help="your API host, e.g. eu2-cloud.acronis.com — must equal the token's audience")
    ap.add_argument("--idempotency-key", help="the Idempotency-Key header you received on the same call")
    ap.add_argument("--digest", help="expected command digest (if you compare against a HexaBox command record)")
    ap.add_argument("--now", help="ISO-8601 time to evaluate at (default: now UTC)")
    a = ap.parse_args(argv)
    token = a.token if a.token else (open(a.token_file).read().strip() if a.token_file else None)
    if not token: ap.error("--token or --token-file required")
    now = _ts(a.now) if a.now else None
    v = verify(token, trusted_pubkey_b64=a.trusted_pubkey, now=now, expected_audience=a.audience,
               expected_idempotency_key=a.idempotency_key, expected_digest=a.digest)
    p = v.get("payload") or {}
    out = {"valid": v["valid"], "reasons": v["reasons"], "signer_id": v.get("signer_id"), "approvers": v.get("approvers"),
           "executor_agent_id": (p.get("executor") or {}).get("agent_id"), "action": (p.get("command") or {}).get("action"),
           "provider_action": (p.get("command") or {}).get("provider_action"), "target": (p.get("command") or {}).get("target"),
           "customer_id": (p.get("command") or {}).get("customer_id"), "audience": p.get("audience"),
           "issued_at": p.get("issued_at"), "expires_at": p.get("expires_at")}
    print(json.dumps(out, indent=2, sort_keys=True)); sys.exit(0 if v["valid"] else 1)

if __name__ == "__main__":
    main()
