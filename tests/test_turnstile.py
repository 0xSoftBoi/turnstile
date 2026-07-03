"""Tests for the TURNSTILE prototype: Def. 1-3, Alg. 1-2, Thm. 3 detectors,
certificate verification, and an end-to-end loopback settlement."""

import asyncio

import pytest
from nacl.signing import SigningKey

from turnstile import (Client, Payment, PodView, Replica, SettleStatus, Vote,
                       conflicting, verify_conflict_proof)
from turnstile.view import HEARTBEAT, verify_certificate, vote_payload

N, BETA, GAMMA = 6, 1, 0


def make_vote(sk: SigningKey, tx_id: str, ts: int, sn: int) -> Vote:
    sig = sk.sign(vote_payload(tx_id, ts, sn)).signature.hex()
    return Vote(tx_id, ts, sn, sig, sk.verify_key.encode().hex())


@pytest.fixture
def replica_keys():
    return [SigningKey.generate() for _ in range(N)]


@pytest.fixture
def sender():
    return SigningKey.generate()


def feed(view, keys, payment, ts_list, sn=1):
    for sk, ts in zip(keys, ts_list):
        view.add_vote(make_vote(sk, payment.tx_id, ts, sn), payment)


def heartbeats(view, keys, ts, sn=99):
    for sk in keys:
        view.add_vote(make_vote(sk, HEARTBEAT, ts, sn))


# ----- payments -------------------------------------------------------------

def test_payment_sign_verify(sender):
    p = Payment.sign(sender, 1, "aa" * 32, 500, "quote")
    assert p.verify()
    assert not Payment(p.S, p.k, p.P, p.v + 1, p.m, p.sig).verify()  # tampered
    assert not Payment(p.S, p.k, p.P, -5, p.m, p.sig).verify()       # v > 0


def test_conflict_relation(sender):
    p = Payment.sign(sender, 7, "aa" * 32, 500, "")
    q = Payment.sign(sender, 7, "bb" * 32, 500, "")
    r = Payment.sign(sender, 8, "bb" * 32, 500, "")
    assert conflicting(p, q) and verify_conflict_proof(p, q)
    assert not conflicting(p, r)      # different k
    assert not conflicting(p, p)      # p != p' required


# ----- settlement predicate --------------------------------------------------

def test_settles_only_past_perfect(replica_keys, sender):
    view = PodView(N, BETA, GAMMA, deposits={sender.verify_key.encode().hex(): 10_000})
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    assert view.traces[p.tx_id].rconf == 12

    # rperf == rconf: strict clause (ii) must hold settlement back
    heartbeats(view, replica_keys, ts=12)
    status, _ = view.settle_check(p)
    assert status is SettleStatus.PENDING
    # ...but the relaxed (<=) variant would pass: exactly the boundary of Remark 1
    status, _ = view.settle_check(p, strict=False)
    assert status is SettleStatus.SETTLED

    view2 = PodView(N, BETA, GAMMA, deposits={sender.verify_key.encode().hex(): 10_000})
    feed(view2, replica_keys[:5], p, [10, 11, 12, 13, 14])
    heartbeats(view2, replica_keys, ts=13)
    status, cert = view2.settle_check(p)
    assert status is SettleStatus.SETTLED
    assert verify_certificate(cert, N, BETA, GAMMA)


def test_unconfirmed_is_pending(replica_keys, sender):
    view = PodView(N, BETA, GAMMA, deposits={sender.verify_key.encode().hex(): 10_000})
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    feed(view, replica_keys[:4], p, [10, 11, 12, 13])   # alpha - 1 votes
    heartbeats(view, replica_keys, ts=50)
    status, _ = view.settle_check(p)
    assert status is SettleStatus.PENDING


def test_conflict_blocks_and_proves(replica_keys, sender):
    view = PodView(N, BETA, GAMMA, deposits={sender.verify_key.encode().hex(): 10_000})
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    q = Payment.sign(sender, 1, "bb" * 32, 500, "")
    feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    view.add_vote(make_vote(replica_keys[5], q.tx_id, 10, 1), q)  # one vote suffices
    heartbeats(view, replica_keys, ts=50)
    status, proof = view.settle_check(p)
    assert status is SettleStatus.REJECTED
    assert verify_conflict_proof(*proof)
    assert len(view.sender_proofs) == 1


def test_insolvency(replica_keys, sender):
    view = PodView(N, BETA, GAMMA, deposits={}, fee=100)
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    heartbeats(view, replica_keys, ts=50)
    status, _ = view.settle_check(p)
    assert status is SettleStatus.INSOLVENT


def test_balance_sequencing(replica_keys, sender):
    S = sender.verify_key.encode().hex()
    view = PodView(N, BETA, GAMMA, deposits={S: 1000}, fee=0)
    p1 = Payment.sign(sender, 1, "aa" * 32, 600, "")
    p2 = Payment.sign(sender, 2, "bb" * 32, 600, "")
    for p in (p1, p2):
        feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    heartbeats(view, replica_keys, ts=50)
    assert view.settle_check(p1)[0] is SettleStatus.SETTLED
    assert view.settle_check(p2)[0] is SettleStatus.INSOLVENT  # 1000 - 600 < 600


def test_replica_equivocation_detector(replica_keys, sender):
    view = PodView(N, BETA, GAMMA)
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    view.add_vote(make_vote(replica_keys[0], p.tx_id, 10, 1), p)
    view.add_vote(make_vote(replica_keys[0], p.tx_id, 20, 2), p)  # fresh (ts, sn)
    assert len(view.replica_proofs) == 1
    v1, v2 = view.replica_proofs[0]
    assert v1.verify() and v2.verify() and v1.rp == v2.rp


def test_forged_votes_ignored(replica_keys, sender):
    view = PodView(N, BETA, GAMMA)
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    good = make_vote(replica_keys[0], p.tx_id, 10, 1)
    forged = Vote(p.tx_id, 10, 1, "00" * 64, replica_keys[1].verify_key.encode().hex())
    view.add_vote(good, p)
    view.add_vote(forged, p)
    assert len(view.votes[p.tx_id]) == 1


def test_rperf_crashed_replica(replica_keys):
    """With gamma-budget omission (one silent replica at n=6, beta=1), rperf
    must still advance off the five live most-recent timestamps."""
    view = PodView(N, BETA, GAMMA)
    heartbeats(view, replica_keys[:5], ts=40)
    assert view.rperf() == 40


# ----- end-to-end over loopback TCP ------------------------------------------

def test_end_to_end_settlement():
    async def run():
        replicas = []
        for _ in range(N):
            r = Replica(SigningKey.generate(), heartbeat_ms=2.0)
            await r.start()
            replicas.append(r)
        sender = SigningKey.generate()
        S = sender.verify_key.encode().hex()
        client = Client([(r.host, r.port) for r in replicas], N, BETA, GAMMA,
                        deposits={S: 10_000}, fee=100, poll_ms=1.0)
        await client.connect()
        await asyncio.sleep(0.1)
        p = Payment.sign(sender, 1, "aa" * 32, 500, "x402-quote-hash")
        await client.write(p)
        status, cert = await client.wait(p, timeout_s=5.0)
        assert status is SettleStatus.SETTLED
        assert verify_certificate(cert, N, BETA, GAMMA)
        assert cert["size_bytes"] == 32 + 5 * Vote.WIRE_BYTES
        await client.close()
        for r in replicas:
            await r.stop()
    asyncio.run(run())


# ----- model checker (quick property) ----------------------------------------

def test_checker_instance():
    from turnstile import checker
    res = checker.run()
    assert res["strict"] == (0, 70)
    assert res["relaxed"][0] == 0
