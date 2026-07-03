"""Benchmark harness: reproduces the experiments of Sec. 9 (Table 1).

Scenarios:
  1. n=6,  beta=1, alpha=5,  loopback          -- settlement latency
  2. n=11, beta=2, alpha=9,  loopback          -- latency vs. n
  3. n=6,  emulated one-way delay 25 ms        -- the 2*delta floor test
  4. n=6,  one replica crashed (gamma budget)  -- liveness under omission
  5. 100 injected sender double-spends         -- Thm. 3(a) detector
  6. 100 injected replica equivocations        -- Thm. 3(b) detector
  7. sustained throughput, single core

Run:  python3 bench.py [--quick]
"""

from __future__ import annotations

import argparse
import asyncio
import statistics
import time

from nacl.signing import SigningKey

from turnstile import Client, Payment, Replica, SettleStatus
from turnstile.payment import verify_conflict_proof
from turnstile.view import verify_certificate

FEE = 100  # $0.0001 in micro-USDC


async def spawn(n: int, heartbeat_ms: float, delay_ms: float = 0.0,
                crash: int = 0, byzantine: int = 0):
    replicas = []
    for i in range(n):
        r = Replica(SigningKey.generate(), heartbeat_ms=heartbeat_ms,
                    delay_ms=delay_ms, byzantine=(i < byzantine))
        if i >= n - crash:
            r.port = 1  # never started: omission-faulty from round 0
        else:
            await r.start()
        replicas.append(r)
    return replicas


async def teardown(replicas, clients):
    for c in clients:
        await c.close()
    for r in replicas:
        if r._server:
            await r.stop()


def pct(xs, p):
    return statistics.quantiles(xs, n=100)[p - 1]


async def latency_run(name: str, n: int, beta: int, gamma: int,
                      payments: int, heartbeat_ms: float, delay_ms: float = 0.0,
                      crash: int = 0, poll_ms: float = 2.0):
    replicas = await spawn(n, heartbeat_ms, delay_ms, crash)
    sender = SigningKey.generate()
    payee = SigningKey.generate().verify_key.encode().hex()
    S = sender.verify_key.encode().hex()
    deposits = {S: 10 ** 12}
    client = Client([(r.host, r.port) for r in replicas], n, beta, gamma,
                    deposits, FEE, poll_ms=poll_ms)
    await client.connect()
    await asyncio.sleep(0.3)  # let heartbeats establish rperf

    lat, cert_size, cert = [], 0, None
    for k in range(1, payments + 1):
        p = Payment.sign(sender, k, payee, v=1000, m=f"quote-{k}")
        t0 = time.perf_counter()
        await client.write(p)
        status, evidence = await client.wait(p, timeout_s=10.0)
        lat.append((time.perf_counter() - t0) * 1000)
        assert status is SettleStatus.SETTLED, f"{name}: k={k} -> {status}"
        cert, cert_size = evidence, evidence["size_bytes"]
    assert verify_certificate(cert, n, beta, gamma), "certificate must verify offline"
    await teardown(replicas, [client])
    print(f"  {name:<34} p50 {pct(lat, 50):7.2f} ms   p90 {pct(lat, 90):7.2f} ms"
          f"   p99 {pct(lat, 99):7.2f} ms   cert {cert_size} B")
    return lat


async def double_spend_run(count: int):
    """Conflicting (S, k) written to disjoint replica subsets; the payee's
    streaming client must observe both and extract the two-signature proof."""
    n, beta, gamma = 6, 1, 0
    replicas = await spawn(n, heartbeat_ms=2.0)
    client = Client([(r.host, r.port) for r in replicas], n, beta, gamma,
                    deposits={}, fee=FEE)
    await client.connect()
    await asyncio.sleep(0.2)

    detected = 0
    for k in range(1, count + 1):
        cheat = SigningKey.generate()
        pa = Payment.sign(cheat, k, "aa" * 32, v=500, m="left")
        pb = Payment.sign(cheat, k, "bb" * 32, v=500, m="right")
        before = len(client.view.sender_proofs)
        await client.write(pa, to=[0, 1, 2])
        await client.write(pb, to=[3, 4, 5])
        for _ in range(500):
            if len(client.view.sender_proofs) > before:
                break
            await asyncio.sleep(0.002)
        proofs = client.view.sender_proofs[before:]
        # verified before counting, as in the paper
        if proofs and all(verify_conflict_proof(x, y) for x, y in proofs):
            status, evidence = client.view.settle_check(pa)
            assert status is SettleStatus.REJECTED
            detected += 1
    await teardown(replicas, [client])
    print(f"  sender double-spends detected        {detected}/{count} "
          f"(two-signature transferable proofs, verified)")
    return detected


async def replica_equivocation_run(count: int):
    """A Byzantine replica re-signs fresh (ts, sn) for a seen transaction."""
    n, beta, gamma = 6, 1, 0
    replicas = await spawn(n, heartbeat_ms=2.0, byzantine=1)
    sender = SigningKey.generate()
    S = sender.verify_key.encode().hex()
    client = Client([(r.host, r.port) for r in replicas], n, beta, gamma,
                    deposits={S: 10 ** 12}, fee=FEE)
    await client.connect()
    await asyncio.sleep(0.2)

    detected = 0
    for k in range(1, count + 1):
        p = Payment.sign(sender, k, "cc" * 32, v=250, m="")
        await client.write(p)
        status, _ = await client.wait(p, timeout_s=5.0)
        assert status is SettleStatus.SETTLED
        before = len(client.view.replica_proofs)
        await client.request_equivocation(0, p.tx_id)
        for _ in range(500):
            if len(client.view.replica_proofs) > before:
                break
            await asyncio.sleep(0.002)
        proofs = client.view.replica_proofs[before:]
        if proofs and all(v1.verify() and v2.verify() and v1.rp == v2.rp
                          for v1, v2 in proofs):
            detected += 1
    await teardown(replicas, [client])
    print(f"  replica equivocations detected       {detected}/{count} "
          f"(two-signature transferable proofs, verified)")
    return detected


async def throughput_run(seconds: float):
    n, beta, gamma = 6, 1, 0
    replicas = await spawn(n, heartbeat_ms=2.0)
    sender = SigningKey.generate()
    S = sender.verify_key.encode().hex()
    payee = "dd" * 32
    client = Client([(r.host, r.port) for r in replicas], n, beta, gamma,
                    deposits={S: 10 ** 15}, fee=FEE, poll_ms=1.0)
    await client.connect()
    await asyncio.sleep(0.2)

    settled, k = 0, 0
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < seconds:
        batch = []
        for _ in range(200):
            k += 1
            batch.append(Payment.sign(sender, k, payee, v=10, m=""))
        for p in batch:
            await client.write(p)
        for p in batch:
            status, _ = await client.wait(p, timeout_s=10.0)
            if status is SettleStatus.SETTLED:
                settled += 1
    dt = time.perf_counter() - t0
    await teardown(replicas, [client])
    print(f"  sustained throughput                 {settled / dt:,.0f} settled payments/s "
          f"({settled} in {dt:.1f} s, single core)")


async def main(quick: bool):
    payments = 50 if quick else 300
    inject = 20 if quick else 100
    print(f"TURNSTILE benchmark ({payments} payments per latency configuration)\n")
    print("Table 1 -- settlement latency (full predicate of Def. 3):")
    await latency_run("n=6,  beta=1, alpha=5, loopback", 6, 1, 0,
                      payments, heartbeat_ms=1.0, poll_ms=0.5)
    await latency_run("n=11, beta=2, alpha=9, loopback", 11, 2, 0,
                      payments, heartbeat_ms=1.0, poll_ms=0.5)
    await latency_run("n=6,  emulated delta=50 ms", 6, 1, 0,
                      max(20, payments // 3), heartbeat_ms=1.0,
                      delay_ms=50.0, poll_ms=0.5)
    await latency_run("n=6,  one replica crashed", 6, 1, 0,
                      payments, heartbeat_ms=1.0, crash=1, poll_ms=0.5)
    print("\nAccountability paths (Thm. 3):")
    assert await double_spend_run(inject) == inject
    assert await replica_equivocation_run(inject) == inject
    print("\nThroughput:")
    await throughput_run(3.0 if quick else 10.0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    asyncio.run(main(ap.parse_args().quick))
