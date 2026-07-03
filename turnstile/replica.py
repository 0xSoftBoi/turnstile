"""A pod replica: stateless with respect to payments.

On a write it assigns its local timestamp and per-replica sequence number,
signs the vote, appends to its log, and streams the vote to all subscribed
clients; it emits one heartbeat vote per round even when idle. There is no
replica-to-replica communication.

Supports an emulated one-way network delay (for the delta-emulation runs)
and a Byzantine mode that re-signs a fresh (ts, sn) for an already-seen
transaction on demand (the replica-equivocation injection of Sec. 9).
"""

from __future__ import annotations

import asyncio
import json
import time

from nacl.signing import SigningKey

from .payment import Payment
from .view import HEARTBEAT, Vote, vote_payload


def now_us() -> int:
    return time.time_ns() // 1_000


class Replica:
    def __init__(self, sk: SigningKey, host: str = "127.0.0.1", port: int = 0,
                 heartbeat_ms: float = 100.0, delay_ms: float = 0.0,
                 byzantine: bool = False):
        self.sk = sk
        self.pk = sk.verify_key.encode().hex()
        self.host, self.port = host, port
        self.heartbeat_s = heartbeat_ms / 1000
        self.delay_s = delay_ms / 1000
        self.byzantine = byzantine
        self.sn = 0
        self.log: list[Vote] = []
        self.seen: dict[str, Vote] = {}          # tx_id -> first vote (log dedup)
        self.subscribers: list[asyncio.StreamWriter] = []
        self._server = None
        self._hb_task = None

    def _vote(self, tx_id: str) -> Vote:
        self.sn += 1
        ts = now_us()
        sig = self.sk.sign(vote_payload(tx_id, ts, self.sn)).signature.hex()
        v = Vote(tx_id, ts, self.sn, sig, self.pk)
        self.log.append(v)
        return v

    def _broadcast(self, msg: dict) -> None:
        data = (json.dumps(msg) + "\n").encode()
        for w in list(self.subscribers):
            if w.is_closing():
                self.subscribers.remove(w)
                continue
            try:
                if self.delay_s:
                    asyncio.get_running_loop().call_later(
                        self.delay_s, self._delayed_write, w, data)
                else:
                    w.write(data)
            except ConnectionError:
                self.subscribers.remove(w)

    @staticmethod
    def _delayed_write(w: asyncio.StreamWriter, data: bytes) -> None:
        try:
            if not w.is_closing():
                w.write(data)
        except ConnectionError:
            pass

    async def _handle_msg(self, msg: dict, writer: asyncio.StreamWriter) -> None:
        kind = msg.get("t")
        if kind == "sub":
            self.subscribers.append(writer)
        elif kind == "write":
            p = Payment.from_dict(msg["pay"])
            if p.tx_id in self.seen:
                vote = self.seen[p.tx_id]      # idempotent re-write
            else:
                vote = self._vote(p.tx_id)
                self.seen[p.tx_id] = vote
            self._broadcast({"t": "v", "vote": vote.to_dict(), "pay": p.to_dict()})
        elif kind == "equivocate" and self.byzantine:
            # Re-sign a fresh (ts, sn) for a seen transaction: the fault
            # the detector of Thm. 3(b) must catch.
            tx_id = msg["tx"]
            if tx_id in self.seen:
                vote = self._vote(tx_id)
                self._broadcast({"t": "v", "vote": vote.to_dict()})

    async def _client_loop(self, reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line)
                if self.delay_s:
                    await asyncio.sleep(self.delay_s)
                await self._handle_msg(msg, writer)
        except (ConnectionError, json.JSONDecodeError):
            pass
        finally:
            if writer in self.subscribers:
                self.subscribers.remove(writer)
            writer.close()

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_s)
            self._broadcast({"t": "v", "vote": self._vote(HEARTBEAT).to_dict()})

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._client_loop, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        self._hb_task = asyncio.create_task(self._heartbeat_loop())

    async def stop(self) -> None:
        if self._hb_task:
            self._hb_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
