"""Pure-python Ed25519 verification (no third-party dependency).

The implementation the bundle's own verify_identity.py uses. It lives here as a
shared module so the RUNTIME (src/shared/ccas_gate.py) can verify asymmetric
approval signatures without importing a root-level CLI script.

Fas 3.25 (external DD, BLOCKING) — this module previously carried the FUNCTIONS
and not the module-level constants they close over. It raised
NameError: name '_p' is not defined on import, ccas_gate swallowed that
exception, and every asymmetric signature therefore verified as False. The
recommended production posture (CCAS_APPROVAL_PUBKEYS bound) could not approve
ANY gated tier, and the red-team attack that was supposed to catch it passed
BECAUSE of the breakage: an attack that only proves a refusal is satisfied by
total failure. The suite now imports this module and verifies a real signature,
so absence of the constants can never again read as security.
"""
import hashlib
from typing import Any

# RFC 8032 curve constants. They are the reason this file cannot be split from
# its functions: every helper below closes over them.
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
