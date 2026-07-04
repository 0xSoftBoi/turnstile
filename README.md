# TURNSTILE

Prototype artifact for **TURNSTILE: A Formally Analyzed Payment Profile over
Consensus-less Validation, with an Interface to Agent Commerce** (working
paper v0.3). It implements the full client and replica logic of §3–4 of the
paper — votes, `rconf` medians, β-padded past-perfection, the strict
settlement predicate, and both equivocation detectors — as a small
Python/asyncio prototype over TCP (Ed25519 via libsodium/PyNaCl), together
with the benchmark harness of §9 and the exhaustive finite-instance model
checker of Remark 1.

The protocol layer is [pod](https://arxiv.org/abs/2501.14931) (Alpos, David,
Mitrovski, Sofikitis, Zindros), used unmodified: clients write to and read
from all `n` replicas directly, with **no replica-to-replica communication**,
and payments settle at the physically optimal `2δ` plus one heartbeat round.
Replicas stay stateless with respect to payments — they timestamp and sign
opaque strings; all payment semantics live in clients and verifiers.

## What is implemented

| Paper object | Code |
|---|---|
| Payment `p = (S, k, P, v, m, σ_S)` (Def. 1), conflict relation (Def. 2), hash locks (§10(1)) | `turnstile/payment.py` |
| Pod view `D = (T, r_perf)`, traces, β-padded medians, settlement predicate (Def. 3 / Alg. 2), detectors (Thm. 3), certificates `SC_p = (C_p, C_pp)` | `turnstile/view.py` |
| Stateless replica: votes, per-replica sequence numbers, heartbeats, Byzantine equivocation mode (Alg. 1 write path) | `turnstile/replica.py` |
| Streaming client: write, reveal preimages, poll `Settled(p, D)` | `turnstile/client.py` |
| x402 facilitator mapping (§7): `/verify`, `/settle`, demo 402 seller | `turnstile/facilitator.py` |
| Checkpoints and the challenge predicate (§6, Alg. 3): epoch balance maps, α-signed roots, equivocation evidence, rollback | `turnstile/checkpoint.py` |
| Exhaustive model checker at `(n, β, γ) = (6, 1, 0)` (§9(4), Remark 1) | `turnstile/checker.py` |
| Benchmark harness (Table 1 + fault/equivocation injections) | `bench.py` |

**Conditional payments (§10(1)).** A payment may carry a hash lock `y`; it
settles only once a preimage `x` with `H(x) = y` is itself written to pod
and past-perfect. Two counterparties atomically exchange payments (PvP) by
conditioning both legs on the same `y` — either both settlement predicates
become satisfiable when `x` appears, or neither ever does. The settlement
certificate then also carries `x` and the preimage's confirmation votes, so
third parties re-verify the lock offline.

**x402 mapping (§7).** `turnstile/facilitator.py` realizes the standard
flow: `402` + quote (quote hash = `m`) → agent signs `p` → facilitator
writes to all replicas → verify = Alg. 2 → settle: serve the resource and
embed `H(C_p)` in `X-PAYMENT-RESPONSE`. The pod settlement certificate is
the payment-proof object x402/AP2 leave abstract; a conflicting spend of
the same `(S, k)` is answered with `409` and the two-signature proof.

**Checkpoints (§6).** Each epoch, every validator evaluates Def. 3 over its
log prefix at the cut, obtaining a balance map `B_e`, and signs
`(e, root(B_e), h_e)` with `h_e` hash-chaining the epoch's certificates; α
matching signatures post as the checkpoint, and a divergent signature is
extractable equivocation evidence. The committed leaf is
`(account, balance, max_k)`, which makes Alg. 3's type-(a) challenge
objective: a valid `SC_p` for payment `(S, k)` plus a Merkle proof that
`S`'s committed `max_k < k` proves the payment's effect absent and rolls
the chain back to `e−1`; a type-(b) conflict-pair challenge additionally
implicates `Σ_e`'s signers. The verifier checks signatures, medians, and
Merkle paths only — it never re-executes payments.

## Quickstart

```bash
pip install -r requirements.txt

python3 -m pytest tests/          # unit + end-to-end tests
python3 -m turnstile.checker      # mechanized check of Theorem 1 at (6,1,0)
python3 bench.py                  # reproduce Table 1 (add --quick for a fast pass)
```

## Measured results (this repository, single interpreted core)

```
Table 1 -- settlement latency (full predicate of Def. 3):
  n=6,  beta=1, alpha=5, loopback    p50    2.62 ms   p90    2.86 ms   p99    4.58 ms   cert 572 B
  n=11, beta=2, alpha=9, loopback    p50    3.98 ms   p90    4.28 ms   p99    5.74 ms   cert 1004 B
  n=6,  emulated delta=50 ms         p50  104.26 ms   p90  105.46 ms   p99  127.72 ms   cert 572 B
  n=6,  one replica crashed          p50    1.92 ms   p90    2.04 ms   p99    2.79 ms   cert 572 B

Accountability paths (Thm. 3):
  sender double-spends detected        100/100 (two-signature transferable proofs, verified)
  replica equivocations detected       100/100 (two-signature transferable proofs, verified)
```

Under an emulated one-way message delay of `δ = 50 ms`, median settlement is
~`2.09δ` against the `2δ = 100 ms` physical floor: the entire payment profile
— signing, vote aggregation, median computation, past-perfection, conflict
scan — costs a few milliseconds above the round trip. With one replica
crashed (the `γ` budget of the `(6,1,0)` point exhausted via omission), every
payment still settles.

The model checker enumerates all 462 honest arrival profiles for two
conflicting payments at `(6,1,0)` over a two-value timestamp domain, crossed
with every adversarial per-client heartbeat horizon (log-prefix rule), free
Byzantine votes per client, and every α-subset each client may aggregate:

```
predicate strict (<):   462 profiles, 0 double settlements
predicate relaxed (<=): 462 profiles, 0 double settlements
```

confirming Theorem 1 mechanically at this instance — and confirming the
paper's Remark 1 that even the relaxed predicate admits no double settlement
here, so strictness is retained because the proof consumes it, not because
the instance demands it.

## How settlement works

A payment is *settled* in a client's view `D = (T, r_perf)` iff (Def. 3):

1. it is **confirmed** — carries votes from `α = n − β − γ` replicas, with
   `r_conf` the median timestamp;
2. `r_conf < r_perf` **strictly** — the past-perfect round has passed it, which
   upgrades "no conflict seen" from absence of evidence to evidence of
   absence;
3. **no conflicting payment** (same `(S, k)`, valid signature) appears in `T`,
   confirmed or not;
4. the sender is **solvent** at sequence number `k`.

Any double-spend attempt yields a transferable two-signature proof against
the sender (Thm. 3a); replica equivocation yields the same against the
replica. A settled payment carries the portable settlement certificate
`SC_p = (C_p, C_pp)`, re-verifiable offline by any third party
(`turnstile.view.verify_certificate`).

## Scope

This is the protocol-overhead prototype of §9: it establishes the floor above
`2δ` on loopback, deliberately separated from network physics. Of the
deployment surface of §6–7, the x402 facilitator mapping and conditional
payments are implemented here; USDC/CCTP funding, hourly netted checkpoints,
the on-chain challenge predicate, and ML-DSA-44 lanes are specified in the
paper and not implemented. Not financial or legal advice.

## License

Apache-2.0 (see `LICENSE`).
