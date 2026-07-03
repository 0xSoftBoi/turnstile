"""Tests for conditional (hash-locked) payments (Sec. 10(1)) and the x402
facilitator mapping (Sec. 7)."""

import asyncio
import json

import pytest
from nacl.signing import SigningKey

from turnstile import (Client, Facilitator, Payment, PodView, Replica,
                       ResourceServer, SettleStatus, hash_lock, preimage_tx_id)
from turnstile.view import verify_certificate
from tests.test_turnstile import feed, heartbeats, make_vote

N, BETA, GAMMA = 6, 1, 0
X = "ab" * 32  # preimage
Y = hash_lock(X)


@pytest.fixture
def replica_keys():
    return [SigningKey.generate() for _ in range(N)]


@pytest.fixture
def sender():
    return SigningKey.generate()


def feed_preimage(view, keys, x, ts_list, sn=50):
    tx_id = preimage_tx_id(x)
    for sk, ts in zip(keys, ts_list):
        view.add_vote(make_vote(sk, tx_id, ts, sn), preimage=x)


def locked_setup(sender, replica_keys, deposits=10_000):
    view = PodView(N, BETA, GAMMA,
                   deposits={sender.verify_key.encode().hex(): deposits})
    p = Payment.sign(sender, 1, "aa" * 32, 500, "pay-for-preimage", y=Y)
    feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    return view, p


def test_lock_holds_without_preimage(replica_keys, sender):
    view, p = locked_setup(sender, replica_keys)
    heartbeats(view, replica_keys, ts=50)
    assert view.settle_check(p)[0] is SettleStatus.PENDING


def test_lock_holds_until_preimage_past_perfect(replica_keys, sender):
    view, p = locked_setup(sender, replica_keys)
    heartbeats(view, replica_keys, ts=20)
    feed_preimage(view, replica_keys[:5], X, [20, 20, 20, 20, 20])
    # preimage confirmed at rconf=20 but rperf=20: not yet past-perfect
    assert view.settle_check(p)[0] is SettleStatus.PENDING
    heartbeats(view, replica_keys, ts=21, sn=60)
    status, cert = view.settle_check(p)
    assert status is SettleStatus.SETTLED
    assert cert["x"] == X and len(cert["C_pre"]) == 5
    assert verify_certificate(cert, N, BETA, GAMMA)


def test_wrong_preimage_does_not_unlock(replica_keys, sender):
    view, p = locked_setup(sender, replica_keys)
    wrong = "cd" * 32
    feed_preimage(view, replica_keys[:5], wrong, [20] * 5)
    heartbeats(view, replica_keys, ts=50)
    assert view.settle_check(p)[0] is SettleStatus.PENDING


def test_certificate_lock_checked_offline(replica_keys, sender):
    view, p = locked_setup(sender, replica_keys)
    heartbeats(view, replica_keys, ts=20)
    feed_preimage(view, replica_keys[:5], X, [20] * 5)
    heartbeats(view, replica_keys, ts=21, sn=60)
    _, cert = view.settle_check(p)
    assert verify_certificate(cert, N, BETA, GAMMA)
    tampered = dict(cert)
    tampered["x"] = "cd" * 32
    assert not verify_certificate(tampered, N, BETA, GAMMA)
    missing = {k: v for k, v in cert.items() if k not in ("x", "C_pre")}
    assert not verify_certificate(missing, N, BETA, GAMMA)


def test_pvp_atomic_exchange(replica_keys):
    """Two counterparties condition payments on the same y: neither settles
    before x appears; both become settleable when it does (PvP, Sec. 10(1))."""
    alice, bob = SigningKey.generate(), SigningKey.generate()
    A = alice.verify_key.encode().hex()
    B = bob.verify_key.encode().hex()
    view = PodView(N, BETA, GAMMA, deposits={A: 10_000, B: 10_000})
    pa = Payment.sign(alice, 1, B, 700, "leg-1", y=Y)
    pb = Payment.sign(bob, 1, A, 900, "leg-2", y=Y)
    for p in (pa, pb):
        feed(view, replica_keys[:5], p, [10, 11, 12, 13, 14])
    heartbeats(view, replica_keys, ts=50)
    assert view.settle_check(pa)[0] is SettleStatus.PENDING
    assert view.settle_check(pb)[0] is SettleStatus.PENDING
    feed_preimage(view, replica_keys[:5], X, [60] * 5)
    heartbeats(view, replica_keys, ts=61, sn=60)
    assert view.settle_check(pa)[0] is SettleStatus.SETTLED
    assert view.settle_check(pb)[0] is SettleStatus.SETTLED


def test_conditional_end_to_end():
    """Reveal over the wire: locked payment pends until the preimage write
    is past-perfect in the streaming client's view."""
    async def run():
        replicas = []
        for _ in range(N):
            r = Replica(SigningKey.generate(), heartbeat_ms=2.0)
            await r.start()
            replicas.append(r)
        sender = SigningKey.generate()
        S = sender.verify_key.encode().hex()
        client = Client([(r.host, r.port) for r in replicas], N, BETA, GAMMA,
                        deposits={S: 10_000}, poll_ms=1.0)
        await client.connect()
        await asyncio.sleep(0.1)
        p = Payment.sign(sender, 1, "aa" * 32, 500, "", y=Y)
        await client.write(p)
        status, _ = await client.wait(p, timeout_s=0.3)
        assert status is SettleStatus.PENDING
        await client.reveal(X)
        status, cert = await client.wait(p, timeout_s=5.0)
        assert status is SettleStatus.SETTLED
        assert verify_certificate(cert, N, BETA, GAMMA)
        await client.close()
        for r in replicas:
            await r.stop()
    asyncio.run(run())


# ----- x402 facilitator flow --------------------------------------------------


async def http_request(port, method, path, headers=None, body=b""):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    lines = [f"{method} {path} HTTP/1.1", "Host: localhost",
             f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    writer.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
    status_line = await reader.readline()
    code = int(status_line.split()[1])
    resp_headers = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        k, _, v = line.decode().partition(":")
        resp_headers[k.strip().lower()] = v.strip()
    payload = await reader.readexactly(int(resp_headers.get("content-length", 0)))
    writer.close()
    return code, resp_headers, json.loads(payload)


def test_x402_flow():
    """Full Sec. 7 mapping: 402 + quote -> agent signs p with m = quote hash
    -> facilitator settles -> resource served with X-PAYMENT-RESPONSE."""
    async def run():
        replicas = []
        for _ in range(N):
            r = Replica(SigningKey.generate(), heartbeat_ms=2.0)
            await r.start()
            replicas.append(r)
        agent = SigningKey.generate()
        S = agent.verify_key.encode().hex()
        payee = SigningKey.generate().verify_key.encode().hex()
        client = Client([(r.host, r.port) for r in replicas], N, BETA, GAMMA,
                        deposits={S: 10_000}, fee=100, poll_ms=1.0)
        await client.connect()
        await asyncio.sleep(0.1)
        fac = Facilitator(client)
        await fac.start()
        seller = ResourceServer(fac, payee, price=500)
        await seller.start()

        # 1. request without payment -> 402 + quote
        code, _, quote_body = await http_request(seller.port, "GET", "/resource")
        assert code == 402
        quote = quote_body["accepts"][0]

        # 2. agent signs a payment with m = quote hash and retries
        p = Payment.sign(agent, 1, payee, quote["maxAmountRequired"],
                         m=quote["quoteHash"])
        code, headers, body = await http_request(
            seller.port, "GET", "/resource",
            headers={"X-PAYMENT": json.dumps(p.to_dict())})
        assert code == 200
        assert body == {"data": "premium bytes"}
        assert len(headers["x-payment-response"]) == 64  # H(C_p)

        # 3. facilitator /verify sees the payment as settled
        code, _, body = await http_request(
            fac.port, "POST", "/verify",
            body=json.dumps({"payment": p.to_dict()}).encode())
        assert code == 200 and body["status"] == "settled"

        # 4. a conflicting payment for the same (S, k) is rejected with proof
        p2 = Payment.sign(agent, 1, "ee" * 32, 500, "elsewhere")
        code, _, body = await http_request(
            fac.port, "POST", "/settle",
            body=json.dumps({"payment": p2.to_dict()}).encode())
        assert code == 409 and body["status"] == "rejected"
        assert len(body["conflictProof"]) == 2

        await seller.stop()
        await fac.stop()
        await client.close()
        for r in replicas:
            await r.stop()
    asyncio.run(run())
