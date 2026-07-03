"""Payment objects (Def. 1), the conflict relation (Def. 2), and the
sender-accountability proof object (Thm. 3a).

A payment is p = (S, k, P, v, m, sigma_S): sender verification key S,
per-sender sequence number k, payee P, amount v > 0, auxiliary data m
(e.g. an x402 quote hash), and S's signature over (S, k, P, v, m).
Replicas treat the serialized payment as an opaque string.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def _payload(S: str, k: int, P: str, v: int, m: str) -> bytes:
    return f"pay|{S}|{k}|{P}|{v}|{m}".encode()


@dataclass(frozen=True)
class Payment:
    S: str      # sender verification key, hex
    k: int      # per-sender sequence number
    P: str      # payee verification key, hex
    v: int      # amount, micro-USDC
    m: str      # auxiliary data (quote hash / AP2 mandate)
    sig: str    # Ed25519 signature by S over (S, k, P, v, m), hex

    @staticmethod
    def sign(sk: SigningKey, k: int, P: str, v: int, m: str = "") -> "Payment":
        S = sk.verify_key.encode().hex()
        sig = sk.sign(_payload(S, k, P, v, m)).signature.hex()
        return Payment(S, k, P, v, m, sig)

    def verify(self) -> bool:
        try:
            VerifyKey(bytes.fromhex(self.S)).verify(
                _payload(self.S, self.k, self.P, self.v, self.m),
                bytes.fromhex(self.sig))
            return self.v > 0
        except (BadSignatureError, ValueError):
            return False

    @property
    def tx_id(self) -> str:
        return hashlib.sha256(
            _payload(self.S, self.k, self.P, self.v, self.m) + bytes.fromhex(self.sig)
        ).hexdigest()

    def to_dict(self) -> dict:
        return {"S": self.S, "k": self.k, "P": self.P, "v": self.v,
                "m": self.m, "sig": self.sig}

    @staticmethod
    def from_dict(d: dict) -> "Payment":
        return Payment(d["S"], int(d["k"]), d["P"], int(d["v"]), d["m"], d["sig"])


def conflicting(p: Payment, q: Payment) -> bool:
    """Def. 2: p != q conflict iff same (S, k) and both validly signed by S."""
    return (p.tx_id != q.tx_id and p.S == q.S and p.k == q.k
            and p.verify() and q.verify())


def verify_conflict_proof(p: Payment, q: Payment) -> bool:
    """Thm. 3a: (p, q) is a transferable proof of misbehavior by sender S,
    checkable by any third party holding S's public key: two signature
    verifications and an equality test on (S, k)."""
    return conflicting(p, q)
