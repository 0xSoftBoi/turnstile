"""Client-side pod view and the TURNSTILE settlement predicate.

Implements, per the paper:
  - votes (tx, ts, sn, sigma, R) and per-transaction traces
    (rmin, rmax, rconf), frozen at confirmation so traces only tighten;
  - beta-padded pessimistic medians and the past-perfect round rperf,
    computed identically over each replica's most-recent timestamp;
  - the settlement predicate Settled(p, D) of Def. 3 / Alg. 2;
  - both equivocation detectors of Thm. 3 (sender and replica), each
    yielding a two-signature transferable proof;
  - the portable settlement certificate SC_p = (C_p, C_pp).

Replicas are stateless with respect to payments; everything here runs in
clients and verifiers.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .payment import Payment, conflicting

NEG_INF = float("-inf")
POS_INF = float("inf")

HEARTBEAT = "hb"


def vote_payload(tx_id: str, ts: int, sn: int) -> bytes:
    return f"vote|{tx_id}|{ts}|{sn}".encode()


@dataclass(frozen=True)
class Vote:
    tx_id: str   # sha256 of the payment (or "hb" for a heartbeat)
    ts: int      # replica-local timestamp (microseconds = rounds)
    sn: int      # per-replica sequence number
    sig: str     # replica signature over (tx_id, ts, sn), hex
    rp: str      # replica verification key, hex

    def verify(self) -> bool:
        try:
            VerifyKey(bytes.fromhex(self.rp)).verify(
                vote_payload(self.tx_id, self.ts, self.sn),
                bytes.fromhex(self.sig))
            return True
        except (BadSignatureError, ValueError):
            return False

    def to_dict(self) -> dict:
        return {"tx": self.tx_id, "ts": self.ts, "sn": self.sn,
                "sig": self.sig, "rp": self.rp}

    @staticmethod
    def from_dict(d: dict) -> "Vote":
        return Vote(d["tx"], int(d["ts"]), int(d["sn"]), d["sig"], d["rp"])

    WIRE_BYTES = 32 + 8 + 4 + 64  # pk + ts + sn + sig, compact encoding


class SettleStatus(enum.Enum):
    PENDING = "pending"
    REJECTED = "rejected"      # conflict observed; proof attached
    INSOLVENT = "insolvent"
    SETTLED = "settled"


def _median_low(xs: list) -> float:
    return sorted(xs)[(len(xs) - 1) // 2]


def _padded_median(ts_list: list, alpha: int, beta: int, extreme: float) -> float:
    """Median over the alpha smallest (extreme=-inf) or largest (+inf)
    timestamps after padding with beta adversarial extremes [pod, Alg. 3]."""
    padded = sorted([extreme] * beta + list(ts_list))
    if extreme == POS_INF:
        window = padded[-alpha:]
    else:
        window = padded[:alpha]
    return _median_low(window)


@dataclass
class Trace:
    rmin: float
    rmax: float
    rconf: float
    votes: dict  # replica -> Vote, the alpha-quorum frozen at confirmation


class PodView:
    """One honest client's pod data structure D = (T, rperf) plus the
    payment-layer state of Def. 3 and the detectors of Thm. 3."""

    def __init__(self, n: int, beta: int, gamma: int,
                 deposits: Optional[dict] = None, fee: int = 0):
        assert n >= 5 * beta + 3 * gamma + 1, "Assumption 1 violated"
        self.n, self.beta, self.gamma = n, beta, gamma
        self.alpha = n - beta - gamma
        self.fee = fee
        self.deposits = dict(deposits or {})

        self.payments: dict[str, Payment] = {}       # tx_id -> Payment (T)
        self.votes: dict[str, dict[str, Vote]] = {}  # tx_id -> replica -> first vote
        self.traces: dict[str, Trace] = {}           # frozen at confirmation
        self.mrt: dict[str, int] = {}                # replica -> most-recent ts
        self.mrt_vote: dict[str, Vote] = {}          # replica -> vote carrying mrt
        self.slots: dict[tuple, set] = {}            # (S, k) -> {tx_id}

        self.sender_proofs: list[tuple[Payment, Payment]] = []
        self.replica_proofs: list[tuple[Vote, Vote]] = []
        self._replica_seq: dict[tuple, Vote] = {}    # (replica, sn) -> vote

        self.settled_out: dict[str, dict[int, int]] = {}  # S -> {k: v+fee}
        self.settled_in: dict[str, int] = {}              # P -> credited sum
        self._settled_ids: set[str] = set()
        self._out_total: dict[str, int] = {}              # sum of settled_out[S]
        self._out_maxk: dict[str, int] = {}               # highest settled k of S

    # ----- ingestion -------------------------------------------------------

    def add_payment(self, p: Payment) -> None:
        """Record a payment in T (does not require confirmation). Detects
        sender equivocation (Thm. 3a) against every prior slot occupant."""
        if p.tx_id in self.payments or not p.verify():
            return
        self.payments[p.tx_id] = p
        slot = self.slots.setdefault((p.S, p.k), set())
        for other_id in slot:
            other = self.payments[other_id]
            if conflicting(p, other):
                self.sender_proofs.append((other, p))
        slot.add(p.tx_id)

    def add_vote(self, vote: Vote, payment: Optional[Payment] = None) -> None:
        """Ingest one replica vote (payment vote or heartbeat). Verifies the
        signature, runs the replica-equivocation detector (Thm. 3b via pod's
        per-replica sequence numbers), advances most-recent timestamps
        monotonically, and freezes the trace at the alpha-th vote."""
        if not vote.verify():
            return

        # Replica equivocation, form 1: two signed votes on one sequence slot.
        prior = self._replica_seq.get((vote.rp, vote.sn))
        if prior is not None:
            if (prior.tx_id, prior.ts) != (vote.tx_id, vote.ts):
                self.replica_proofs.append((prior, vote))
            # first vote per slot is binding either way
        else:
            self._replica_seq[(vote.rp, vote.sn)] = vote

        # Most-recent timestamp only advances (monotonicity).
        if vote.ts > self.mrt.get(vote.rp, -1):
            self.mrt[vote.rp] = vote.ts
            self.mrt_vote[vote.rp] = vote

        if vote.tx_id == HEARTBEAT:
            return

        if payment is not None:
            add = payment.tx_id == vote.tx_id
            if add:
                self.add_payment(payment)

        per_tx = self.votes.setdefault(vote.tx_id, {})
        prior_tx = per_tx.get(vote.rp)
        if prior_tx is not None:
            # Replica equivocation, form 2: re-signing fresh (ts, sn) for a
            # transaction it already voted on.
            if (prior_tx.ts, prior_tx.sn) != (vote.ts, vote.sn):
                self.replica_proofs.append((prior_tx, vote))
            return
        per_tx[vote.rp] = vote

        # Confirmation: freeze (rmin, rmax, rconf) over the alpha-quorum.
        if vote.tx_id not in self.traces and len(per_tx) >= self.alpha:
            quorum = dict(list(per_tx.items())[: self.alpha])
            ts_list = [v.ts for v in quorum.values()]
            self.traces[vote.tx_id] = Trace(
                rmin=_padded_median(ts_list, self.alpha, self.beta, NEG_INF),
                rmax=_padded_median(ts_list, self.alpha, self.beta, POS_INF),
                rconf=_median_low(ts_list),
                votes=quorum,
            )

    # ----- derived quantities ---------------------------------------------

    def rperf(self) -> float:
        """Past-perfect round: computed identically to rmin over each
        replica's most-recent timestamp [pod, Alg. 3]."""
        if self.beta + len(self.mrt) < self.alpha:
            return NEG_INF
        return _padded_median(list(self.mrt.values()),
                              self.alpha, self.beta, NEG_INF)

    def rconf(self, tx_id: str) -> Optional[float]:
        t = self.traces.get(tx_id)
        return t.rconf if t else None

    def find_conflict(self, p: Payment) -> Optional[Payment]:
        """Def. 3(iii): any payment conflicting with p in T, confirmed or not."""
        for other_id in self.slots.get((p.S, p.k), ()):
            if other_id != p.tx_id:
                other = self.payments[other_id]
                if conflicting(p, other):
                    return other
        return None

    def balance(self, S: str, k: int) -> int:
        """bal_D(S, k): deposits plus settled credits, minus S's settled
        payments with sequence numbers < k (Def. 3(iv))."""
        if k > self._out_maxk.get(S, -1):
            out = self._out_total.get(S, 0)   # common case: next in sequence
        else:
            out = sum(cost for kk, cost in self.settled_out.get(S, {}).items()
                      if kk < k)
        return self.deposits.get(S, 0) + self.settled_in.get(S, 0) - out

    # ----- Alg. 2: SettleCheck ---------------------------------------------

    def settle_check(self, p: Payment, strict: bool = True):
        """Evaluate Settled(p, D). Returns (status, evidence) where evidence
        is the conflict proof on REJECTED and the settlement certificate
        SC_p = (C_p, C_pp) on SETTLED."""
        self.add_payment(p)
        conflict = self.find_conflict(p)
        if conflict is not None:
            return SettleStatus.REJECTED, (p, conflict)
        trace = self.traces.get(p.tx_id)
        if trace is None:
            return SettleStatus.PENDING, None                 # Def. 3(i)
        rp = self.rperf()
        if (trace.rconf >= rp) if strict else (trace.rconf > rp):
            return SettleStatus.PENDING, None                 # Def. 3(ii)
        if self.balance(p.S, p.k) < p.v + self.fee:
            return SettleStatus.INSOLVENT, None               # Def. 3(iv)
        if p.tx_id not in self._settled_ids:
            self._settled_ids.add(p.tx_id)
            cost = p.v + self.fee
            self.settled_out.setdefault(p.S, {})[p.k] = cost
            self.settled_in[p.P] = self.settled_in.get(p.P, 0) + p.v
            self._out_total[p.S] = self._out_total.get(p.S, 0) + cost
            self._out_maxk[p.S] = max(self._out_maxk.get(p.S, -1), p.k)
        cert = self.certificate(p)
        return SettleStatus.SETTLED, cert

    def certificate(self, p: Payment) -> dict:
        """Portable settlement certificate SC_p = (C_p, C_pp): the
        alpha-quorum confirmation votes plus the past-perfection votes
        (each replica's most-recent-timestamp vote) of the settling view."""
        trace = self.traces[p.tx_id]
        c_p = [v.to_dict() for v in trace.votes.values()]
        c_pp = [v.to_dict() for v in self.mrt_vote.values()]
        return {
            "payment": p.to_dict(),
            "C_p": c_p,
            "C_pp": c_pp,
            # Table 1 "certificate" column: C_p alone (tx hash + alpha votes)
            "size_bytes": 32 + len(c_p) * Vote.WIRE_BYTES,
            # full portable settlement certificate SC_p = (C_p, C_pp)
            "sc_size_bytes": 32 + (len(c_p) + len(c_pp)) * Vote.WIRE_BYTES,
        }


def verify_certificate(cert: dict, n: int, beta: int, gamma: int) -> bool:
    """Offline third-party check in the spirit of pod's valid(D, C): re-derive
    the view fragment from the certificate and re-evaluate Def. 3(i)-(iii)."""
    alpha = n - beta - gamma
    p = Payment.from_dict(cert["payment"])
    if not p.verify():
        return False
    c_p = [Vote.from_dict(d) for d in cert["C_p"]]
    c_pp = [Vote.from_dict(d) for d in cert["C_pp"]]
    if any(not v.verify() for v in c_p + c_pp):
        return False
    if len({v.rp for v in c_p if v.tx_id == p.tx_id}) < alpha:
        return False
    rconf = _median_low([v.ts for v in c_p])
    mrt: dict[str, int] = {}
    for v in c_pp:
        mrt[v.rp] = max(mrt.get(v.rp, -1), v.ts)
    if beta + len(mrt) < alpha:
        return False
    rperf = _padded_median(list(mrt.values()), alpha, beta, NEG_INF)
    return rconf < rperf
