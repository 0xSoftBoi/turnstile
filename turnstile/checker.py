"""Exhaustive finite-instance model checker for Theorem 1 (Sec. 9(4)).

Instance (n, beta, gamma) = (6, 1, 0), alpha = 5, two-value timestamp
domain {1, 2}, two conflicting payments p and q (same (S, k), both validly
signed). Enumerated, per the paper:

  - all 462 honest arrival profiles: each of the 5 honest replicas takes
    one of 7 arrival options (neither payment; p or q alone at ts 1 or 2;
    both, in either order -- per-replica sequence numbers force distinct
    timestamps), and replicas are interchangeable, so profiles are
    multisets: C(5+7-1, 5) = 462;
  - every adversarial choice of per-client delivered heartbeat horizons,
    with the log-prefix rule enforced (a client that has replica R's log
    through round h holds exactly R's votes with ts <= h, and R's
    most-recent timestamp is h);
  - free Byzantine votes and heartbeats per client (the one Byzantine
    replica may show each client any vote timestamp in {1, 2} or nothing,
    independently);
  - every alpha-subset each client may aggregate for confirmation.

A client settles its payment iff Def. 3 holds on its delivered view:
confirmed by an alpha-quorum, rconf < rperf (strict; the relaxed variant
uses <=), and no vote for the conflicting payment is visible (clause iii).
Deliveries to the two clients are independent, so a double settlement at a
profile is: some delivery settles p at client 1 AND some delivery settles
q at client 2.

Expected result (paper, Sec. 9): zero double settlements under the strict
predicate, and zero under the relaxed (<=) predicate as well.
"""

from __future__ import annotations

import itertools
from typing import Optional

N, BETA, GAMMA = 6, 1, 0
ALPHA = N - BETA - GAMMA          # 5
HONEST = N - BETA                 # 5
TS_DOMAIN = (1, 2)
NEG_INF = float("-inf")

# Per-replica arrival options: (ts of p or None, ts of q or None).
OPTIONS = [
    (None, None),                 # neither
    (1, None), (2, None),         # p alone
    (None, 1), (None, 2),         # q alone
    (1, 2), (2, 1),               # both; sequence numbers force tp != tq
]


def _median_low(xs) -> float:
    s = sorted(xs)
    return s[(len(s) - 1) // 2]


def _rperf(mrts) -> float:
    """Identical computation to the client's: pad with beta adversarial
    -inf entries, take the median of the alpha smallest."""
    padded = sorted([NEG_INF] * BETA + list(mrts))
    if len(padded) < ALPHA:
        return NEG_INF
    return _median_low(padded[:ALPHA])


def _replica_states(arrival, target: int):
    """Distinct delivered states of one honest replica for one client, over
    horizons h in {0, 1, 2} (log-prefix rule): (target vote ts or None,
    conflicting vote visible?, mrt or None)."""
    t_ts, o_ts = (arrival[target], arrival[1 - target])
    states = set()
    for h in (0,) + TS_DOMAIN:
        tv = t_ts if (t_ts is not None and t_ts <= h) else None
        ov = o_ts is not None and o_ts <= h
        mrt = h if h >= 1 else None
        states.add((tv, ov, mrt))
    return sorted(states, key=str)


def can_settle(profile, target: int, strict: bool) -> bool:
    """Does some adversarial delivery let a client settle `target`
    (0 for p, 1 for q) under the given predicate variant?"""
    per_replica = [_replica_states(arr, target) for arr in profile]
    # Byzantine replica: any target-payment vote in {None, 1, 2} crossed
    # with any heartbeat horizon in {None, 1, 2}. It never shows this
    # client the conflicting payment (that could only block settlement).
    byz_choices = [(bv, bh) for bv in (None,) + TS_DOMAIN
                   for bh in (None,) + TS_DOMAIN]
    for states in itertools.product(*per_replica):
        if any(ov for (_, ov, _) in states):
            continue                            # Def. 3(iii) fails
        for bv, bh in byz_choices:
            votes = [tv for (tv, _, _) in states if tv is not None]
            if bv is not None:
                votes.append(bv)
            if len(votes) < ALPHA:
                continue                        # Def. 3(i) fails
            mrts = [m for (_, _, m) in states if m is not None]
            b_mrt = max((x for x in (bv, bh) if x is not None), default=None)
            if b_mrt is not None:
                mrts.append(b_mrt)
            rperf = _rperf(mrts)
            for quorum in itertools.combinations(votes, ALPHA):
                rconf = _median_low(quorum)
                if (rconf < rperf) if strict else (rconf <= rperf):
                    return True
    return False


def run(progress: bool = False):
    profiles = list(
        itertools.combinations_with_replacement(range(len(OPTIONS)), HONEST))
    assert len(profiles) == 462
    results = {}
    for strict in (True, False):
        doubles = 0
        single = 0
        for idx in profiles:
            profile = [OPTIONS[i] for i in idx]
            sp = can_settle(profile, 0, strict)
            sq = can_settle(profile, 1, strict)
            if sp and sq:
                doubles += 1
            if sp or sq:
                single += 1
        results["strict" if strict else "relaxed"] = (doubles, single)
        if progress:
            name = "strict (<)" if strict else "relaxed (<=)"
            print(f"predicate {name}: {len(profiles)} profiles, "
                  f"{doubles} double settlements, "
                  f"{single} profiles where some payment can settle")
    return results


if __name__ == "__main__":
    res = run(progress=True)
    assert res["strict"][0] == 0, "Theorem 1 REFUTED at (6,1,0)!"
    assert res["strict"][1] > 0, "vacuous check: nothing ever settles"
    print("Theorem 1 confirmed mechanically at (6,1,0); "
          "relaxed predicate also admits no double settlement."
          if res["relaxed"][0] == 0 else
          "Strictness is load-bearing at (6,1,0): relaxed predicate fails.")
