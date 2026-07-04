"""Checkpoints and the settlement bridge's challenge predicate (Sec. 6, Alg. 3).

Each epoch e, every validator evaluates Def. 3 over its log prefix at the
epoch cut, obtaining a balance map B_e, and signs (e, root(B_e), h_e) with
h_e hash-chaining the epoch's certificates; alpha matching signatures post
as the checkpoint. Because settlement is an objective function of
certificates (Thm. 1), honest validators cannot durably diverge; a
divergent signature is either resolvable from certificates or is
equivocation evidence.

The committed leaf for account a is (a, balance, max_k), where max_k is
the highest settled sender sequence number of a at the cut. This makes the
type-(a) challenge of Alg. 3 objective and O(alpha)-verifiable offline: a
settlement certificate SC_p valid for payment (S, k) with confirmed round
before the cut, together with a Merkle proof that S's committed max_k < k,
proves p's effect absent from root(B_e).

The challenge predicate here is the off-chain verifier the on-chain
contract would run; it never re-executes payments -- it verifies
signatures, medians, and Merkle paths.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .payment import Payment, verify_conflict_proof
from .view import PodView, verify_certificate


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ----- balance map and Merkle commitment --------------------------------------

@dataclass(frozen=True)
class BalanceLeaf:
    account: str
    balance: int
    max_k: int      # highest settled sender sequence number, -1 if none

    def digest(self) -> str:
        return _h(f"leaf|{self.account}|{self.balance}|{self.max_k}".encode())


def balance_map(view: PodView) -> list[BalanceLeaf]:
    """B_e: Def. 3 evaluated over the view's log prefix at the cut."""
    accounts = (set(view.deposits) | set(view.settled_in)
                | set(view.settled_out))
    leaves = []
    for a in sorted(accounts):
        out = view.settled_out.get(a, {})
        bal = (view.deposits.get(a, 0) + view.settled_in.get(a, 0)
               - sum(out.values()))
        leaves.append(BalanceLeaf(a, bal, max(out, default=-1)))
    return leaves


def merkle_root(leaves: list[BalanceLeaf]) -> str:
    level = [leaf.digest() for leaf in leaves] or [_h(b"empty")]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_h((level[i] + level[i + 1]).encode())
                 for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaves: list[BalanceLeaf], account: str) -> list[tuple[str, bool]]:
    """Path of (sibling digest, sibling-is-right) pairs for the account's leaf."""
    idx = next(i for i, leaf in enumerate(leaves) if leaf.account == account)
    level = [leaf.digest() for leaf in leaves]
    path = []
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sib = idx + 1 if idx % 2 == 0 else idx - 1
        path.append((level[sib], sib > idx))
        level = [_h((level[i] + level[i + 1]).encode())
                 for i in range(0, len(level), 2)]
        idx //= 2
    return path


def verify_merkle(root: str, leaf: BalanceLeaf,
                  path: list[tuple[str, bool]]) -> bool:
    node = leaf.digest()
    for sibling, is_right in path:
        node = _h((node + sibling).encode() if is_right
                  else (sibling + node).encode())
    return node == root


# ----- validator signatures and checkpoint assembly ----------------------------

def _ckpt_payload(e: int, root: str, h_e: str) -> bytes:
    return f"ckpt|{e}|{root}|{h_e}".encode()


@dataclass(frozen=True)
class CheckpointSig:
    e: int
    root: str
    h_e: str      # hash chain over the epoch's certificates
    sig: str
    vp: str       # validator verification key, hex

    def verify(self) -> bool:
        try:
            VerifyKey(bytes.fromhex(self.vp)).verify(
                _ckpt_payload(self.e, self.root, self.h_e),
                bytes.fromhex(self.sig))
            return True
        except (BadSignatureError, ValueError):
            return False


@dataclass(frozen=True)
class Checkpoint:
    e: int
    root: str
    h_e: str
    sigs: tuple  # Sigma_e: alpha matching CheckpointSig


class Validator:
    """A checkpoint validator: an honest streaming client that additionally
    signs its epoch-cut balance map."""

    def __init__(self, sk: SigningKey, view: PodView):
        self.sk = sk
        self.pk = sk.verify_key.encode().hex()
        self.view = view

    def epoch_hash(self, prev_h: str) -> str:
        """h_e: hash-chain the epoch's settled certificates (by tx id)."""
        settled = sorted(self.view._settled_ids)
        return _h((prev_h + "|" + "|".join(settled)).encode())

    def sign_checkpoint(self, e: int, prev_h: str) -> CheckpointSig:
        leaves = balance_map(self.view)
        root = merkle_root(leaves)
        h_e = self.epoch_hash(prev_h)
        sig = self.sk.sign(_ckpt_payload(e, root, h_e)).signature.hex()
        return CheckpointSig(e, root, h_e, sig, self.pk)


def assemble_checkpoint(sigs: list[CheckpointSig],
                        alpha: int) -> Optional[Checkpoint]:
    """alpha matching, validly signed signatures from distinct validators
    post as the checkpoint."""
    groups: dict[tuple, dict[str, CheckpointSig]] = {}
    for s in sigs:
        if s.verify():
            groups.setdefault((s.e, s.root, s.h_e), {})[s.vp] = s
    for (e, root, h_e), members in groups.items():
        if len(members) >= alpha:
            return Checkpoint(e, root, h_e, tuple(members.values()))
    return None


def checkpoint_equivocation(a: CheckpointSig,
                            b: CheckpointSig) -> bool:
    """Two valid signatures by one validator on divergent epoch-e roots:
    transferable equivocation evidence (Sec. 6)."""
    return (a.vp == b.vp and a.e == b.e
            and (a.root, a.h_e) != (b.root, b.h_e)
            and a.verify() and b.verify())


# ----- Alg. 3: the challenge predicate -----------------------------------------

@dataclass
class ChallengeResult:
    accepted: bool
    reason: str
    implicated: tuple = ()   # Sigma_e signers to slash (type (b) only)


def challenge_type_a(ckpt: Checkpoint, cert: dict, leaf: BalanceLeaf,
                     path: list[tuple[str, bool]],
                     n: int, beta: int, gamma: int) -> ChallengeResult:
    """Alg. 3(a): a payment p and certificate SC_p, valid accepting, such
    that Settled evaluated on the certified data contradicts the absence of
    p's effect in root(B_e). The verifier runs O(alpha) signature checks,
    medians, and one Merkle path -- it never re-executes payments."""
    if not verify_certificate(cert, n, beta, gamma):
        return ChallengeResult(False, "certificate does not verify")
    p = Payment.from_dict(cert["payment"])
    if not verify_merkle(ckpt.root, leaf, path):
        return ChallengeResult(False, "Merkle proof does not verify")
    if leaf.account != p.S:
        return ChallengeResult(False, "leaf is not the payment's sender")
    if leaf.max_k >= p.k:
        return ChallengeResult(False, "payment's effect present in B_e")
    return ChallengeResult(True, "settled payment absent from checkpoint")


def challenge_type_b(ckpt: Checkpoint, proof: tuple,
                     leaf: BalanceLeaf,
                     path: list[tuple[str, bool]]) -> ChallengeResult:
    """Alg. 3(b): a conflict pair (Thm. 3a) affecting a balance in B_e.
    On accept, Sigma_e's signers are implicated."""
    p, q = proof
    if not verify_conflict_proof(p, q):
        return ChallengeResult(False, "conflict pair does not verify")
    if not verify_merkle(ckpt.root, leaf, path):
        return ChallengeResult(False, "Merkle proof does not verify")
    if leaf.account != p.S or leaf.max_k < p.k:
        return ChallengeResult(False, "no conflicting payment's effect in B_e")
    return ChallengeResult(True, "equivocating sender's payment in B_e",
                           implicated=tuple(s.vp for s in ckpt.sigs))


class CheckpointChain:
    """The bridge's view of posted checkpoints: append alpha-signed epochs,
    roll back to e-1 on an accepted challenge (Alg. 3)."""

    def __init__(self, alpha: int):
        self.alpha = alpha
        self.checkpoints: list[Checkpoint] = []

    @property
    def head(self) -> Optional[Checkpoint]:
        return self.checkpoints[-1] if self.checkpoints else None

    def post(self, sigs: list[CheckpointSig]) -> Optional[Checkpoint]:
        ckpt = assemble_checkpoint(sigs, self.alpha)
        if ckpt is None:
            return None
        expected = self.head.e + 1 if self.head else 0
        if ckpt.e != expected:
            return None
        self.checkpoints.append(ckpt)
        return ckpt

    def challenge(self, result: ChallengeResult) -> tuple:
        """On an accepted challenge: roll back to checkpoint e-1 and return
        the implicated signers (empty for type (a))."""
        if not result.accepted or not self.checkpoints:
            return ()
        self.checkpoints.pop()
        return result.implicated
