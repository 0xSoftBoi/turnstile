"""Tests for the Sec. 6 checkpoint layer and the Alg. 3 challenge predicate."""

import pytest
from nacl.signing import SigningKey

from turnstile import Payment, PodView, SettleStatus
from turnstile.checkpoint import (BalanceLeaf, CheckpointChain, Validator,
                                  assemble_checkpoint, balance_map,
                                  challenge_type_a, challenge_type_b,
                                  checkpoint_equivocation, merkle_proof,
                                  merkle_root, verify_merkle)
from tests.test_turnstile import feed, heartbeats

N, BETA, GAMMA = 6, 1, 0
ALPHA = N - BETA - GAMMA
GENESIS_H = "00" * 32


@pytest.fixture
def replica_keys():
    return [SigningKey.generate() for _ in range(N)]


@pytest.fixture
def sender():
    return SigningKey.generate()


def settled_view(replica_keys, sender, ks=(1,)):
    """A view in which payments at sequence numbers `ks` are settled."""
    S = sender.verify_key.encode().hex()
    view = PodView(N, BETA, GAMMA, deposits={S: 10_000}, fee=0)
    for k in ks:
        p = Payment.sign(sender, k, "aa" * 32, 500, "")
        feed(view, replica_keys[:5], p, [10 * k + d for d in range(5)], sn=k)
    heartbeats(view, replica_keys, ts=10_000)
    for k in ks:
        p = Payment.sign(sender, k, "aa" * 32, 500, "")
        assert view.settle_check(p)[0] is SettleStatus.SETTLED
    return view, S


def test_merkle_membership(replica_keys, sender):
    view, S = settled_view(replica_keys, sender, ks=(1, 2))
    leaves = balance_map(view)
    root = merkle_root(leaves)
    for leaf in leaves:
        path = merkle_proof(leaves, leaf.account)
        assert verify_merkle(root, leaf, path)
    # tampered leaf fails
    bad = BalanceLeaf(leaves[0].account, leaves[0].balance + 1, leaves[0].max_k)
    assert not verify_merkle(root, bad, merkle_proof(leaves, leaves[0].account))


def test_honest_validators_agree(replica_keys, sender):
    """Settlement is an objective function of certificates: identical views
    yield identical roots, and alpha signatures assemble a checkpoint."""
    view, S = settled_view(replica_keys, sender)
    validators = [Validator(SigningKey.generate(), view) for _ in range(N)]
    sigs = [v.sign_checkpoint(0, GENESIS_H) for v in validators]
    assert len({(s.root, s.h_e) for s in sigs}) == 1
    ckpt = assemble_checkpoint(sigs[:ALPHA], ALPHA)
    assert ckpt is not None and ckpt.e == 0


def test_divergent_signature_is_evidence(replica_keys, sender):
    view, S = settled_view(replica_keys, sender)
    stale = PodView(N, BETA, GAMMA, deposits={S: 10_000}, fee=0)  # empty view
    cheat = SigningKey.generate()
    s1 = Validator(cheat, view).sign_checkpoint(0, GENESIS_H)
    s2 = Validator(cheat, stale).sign_checkpoint(0, GENESIS_H)
    assert checkpoint_equivocation(s1, s2)
    honest = Validator(SigningKey.generate(), view).sign_checkpoint(0, GENESIS_H)
    assert not checkpoint_equivocation(s1, honest)  # distinct validators
    assert not checkpoint_equivocation(s1, s1)      # same object


def test_challenge_type_a_omitted_payment(replica_keys, sender):
    """A checkpoint built from a view that missed a settled payment is
    defeated by SC_p plus a Merkle proof that max_k < k."""
    view, S = settled_view(replica_keys, sender, ks=(1,))
    _, cert = view.settle_check(Payment.sign(sender, 1, "aa" * 32, 500, ""))

    # dishonest/stale checkpoint: deposits only, no settled payments
    stale = PodView(N, BETA, GAMMA, deposits={S: 10_000}, fee=0)
    stale_sigs = [Validator(SigningKey.generate(), stale)
                  .sign_checkpoint(0, GENESIS_H) for _ in range(ALPHA)]
    chain = CheckpointChain(ALPHA)
    ckpt = chain.post(stale_sigs)
    assert ckpt is not None

    stale_leaves = balance_map(stale)
    leaf = next(l for l in stale_leaves if l.account == S)
    assert leaf.max_k == -1
    res = challenge_type_a(ckpt, cert, leaf,
                           merkle_proof(stale_leaves, S), N, BETA, GAMMA)
    assert res.accepted
    chain.challenge(res)
    assert chain.head is None  # rolled back to e-1


def test_challenge_type_a_rejected_when_effect_present(replica_keys, sender):
    view, S = settled_view(replica_keys, sender, ks=(1,))
    _, cert = view.settle_check(Payment.sign(sender, 1, "aa" * 32, 500, ""))
    sigs = [Validator(SigningKey.generate(), view)
            .sign_checkpoint(0, GENESIS_H) for _ in range(ALPHA)]
    chain = CheckpointChain(ALPHA)
    ckpt = chain.post(sigs)
    leaves = balance_map(view)
    leaf = next(l for l in leaves if l.account == S)
    res = challenge_type_a(ckpt, cert, leaf, merkle_proof(leaves, S),
                           N, BETA, GAMMA)
    assert not res.accepted and "present" in res.reason
    assert chain.challenge(res) == () and chain.head is ckpt


def test_challenge_type_b_conflict_pair(replica_keys, sender):
    """A checkpoint reflecting an equivocating sender's payment is defeated
    by the Thm. 3a pair; Sigma_e's signers are implicated."""
    view, S = settled_view(replica_keys, sender, ks=(1,))
    sigs = [Validator(SigningKey.generate(), view)
            .sign_checkpoint(0, GENESIS_H) for _ in range(ALPHA)]
    chain = CheckpointChain(ALPHA)
    ckpt = chain.post(sigs)

    p = Payment.sign(sender, 1, "aa" * 32, 500, "")       # the settled leg
    q = Payment.sign(sender, 1, "bb" * 32, 500, "other")  # the hidden leg
    leaves = balance_map(view)
    leaf = next(l for l in leaves if l.account == S)
    res = challenge_type_b(ckpt, (p, q), leaf, merkle_proof(leaves, S))
    assert res.accepted
    implicated = chain.challenge(res)
    assert set(implicated) == {s.vp for s in ckpt.sigs}
    assert chain.head is None


def test_challenge_type_b_needs_valid_pair(replica_keys, sender):
    view, S = settled_view(replica_keys, sender, ks=(1,))
    sigs = [Validator(SigningKey.generate(), view)
            .sign_checkpoint(0, GENESIS_H) for _ in range(ALPHA)]
    ckpt = CheckpointChain(ALPHA).post(sigs)
    p = Payment.sign(sender, 1, "aa" * 32, 500, "")
    r = Payment.sign(sender, 2, "bb" * 32, 500, "")   # different k: no conflict
    leaves = balance_map(view)
    leaf = next(l for l in leaves if l.account == S)
    res = challenge_type_b(ckpt, (p, r), leaf, merkle_proof(leaves, S))
    assert not res.accepted


def test_epoch_sequencing(replica_keys, sender):
    view, S = settled_view(replica_keys, sender)
    chain = CheckpointChain(ALPHA)
    vals = [Validator(SigningKey.generate(), view) for _ in range(ALPHA)]
    assert chain.post([v.sign_checkpoint(1, GENESIS_H) for v in vals]) is None
    ck0 = chain.post([v.sign_checkpoint(0, GENESIS_H) for v in vals])
    assert ck0 is not None
    ck1 = chain.post([v.sign_checkpoint(1, ck0.h_e) for v in vals])
    assert ck1 is not None and chain.head is ck1
