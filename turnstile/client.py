"""A streaming TURNSTILE client (Alg. 1 write path + Alg. 2 settle path).

Connects to all n replicas, subscribes to their vote streams, maintains a
PodView, and exposes:
  write(p)            -- one client-to-replicas trip, no further sender action
  wait(p)             -- poll Settled(p, D) until settled/rejected/timeout
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from .payment import Payment
from .view import PodView, SettleStatus, Vote


class Client:
    def __init__(self, endpoints: list[tuple[str, int]], n: int, beta: int,
                 gamma: int, deposits: Optional[dict] = None, fee: int = 0,
                 poll_ms: float = 2.0):
        self.endpoints = endpoints
        self.view = PodView(n, beta, gamma, deposits, fee)
        self.poll_s = poll_ms / 1000
        self._conns: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []
        self._readers: list[asyncio.Task] = []

    async def connect(self) -> None:
        for host, port in self.endpoints:
            try:
                reader, writer = await asyncio.open_connection(host, port)
            except ConnectionError:
                continue  # crashed / unreachable replica: omission fault
            writer.write(b'{"t": "sub"}\n')
            self._conns.append((reader, writer))
            self._readers.append(asyncio.create_task(self._stream(reader)))

    async def _stream(self, reader: asyncio.StreamReader) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line)
                if msg.get("t") != "v":
                    continue
                vote = Vote.from_dict(msg["vote"])
                pay = Payment.from_dict(msg["pay"]) if "pay" in msg else None
                self.view.add_vote(vote, pay)
        except (ConnectionError, json.JSONDecodeError, asyncio.CancelledError):
            pass

    async def write(self, p: Payment, to: Optional[list[int]] = None) -> None:
        """Alg. 1: send p to all n replicas (or, for the double-spend
        injection, to the indexed subset `to`)."""
        data = (json.dumps({"t": "write", "pay": p.to_dict()}) + "\n").encode()
        conns = self._conns if to is None else [self._conns[i] for i in to]
        for _, writer in conns:
            writer.write(data)

    async def request_equivocation(self, replica_idx: int, tx_id: str) -> None:
        _, writer = self._conns[replica_idx]
        writer.write((json.dumps({"t": "equivocate", "tx": tx_id}) + "\n").encode())

    async def wait(self, p: Payment, timeout_s: float = 5.0):
        """Poll the settlement predicate until it leaves PENDING."""
        deadline = asyncio.get_running_loop().time() + timeout_s
        while True:
            status, evidence = self.view.settle_check(p)
            if status is not SettleStatus.PENDING:
                return status, evidence
            if asyncio.get_running_loop().time() > deadline:
                return status, evidence
            await asyncio.sleep(self.poll_s)

    async def close(self) -> None:
        for task in self._readers:
            task.cancel()
        for _, writer in self._conns:
            writer.close()
