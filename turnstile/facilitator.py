"""x402 facilitator mapping (Sec. 7).

Realizes the standard x402 flow over TURNSTILE:

    402 + quote (quote hash = m)
      -> agent signs p (Def. 1)
      -> facilitator writes to all replicas (Alg. 1)
      -> verify = Alg. 2
      -> settle: serve the resource, embed H(C_p) in X-PAYMENT-RESPONSE

Two servers are provided over a minimal dependency-free asyncio HTTP/1.1
layer:

  Facilitator  -- POST /verify  {payment}: evaluate Alg. 2 on the current
                                view without writing;
                  POST /settle  {payment}: write, await settlement, return
                                the certificate and its hash.
  ResourceServer -- a demo x402 seller: GET <path> without X-PAYMENT
                  returns 402 with a quote; with a signed payment whose
                  m equals the quote hash it settles via the facilitator
                  and serves the resource with X-PAYMENT-RESPONSE: H(C_p).

The pod settlement certificate is the payment-proof object x402/AP2 leave
abstract; AP2 mandates ride in m.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Callable, Optional

from .client import Client
from .payment import Payment
from .view import SettleStatus


class _HTTPServer:
    """Tiny asyncio HTTP/1.1 JSON server (enough for the x402 flow)."""

    def __init__(self, handler: Callable, host: str = "127.0.0.1", port: int = 0):
        self._handler = handler   # async (method, path, headers, body) -> (code, hdrs, body)
        self.host, self.port = host, port
        self._server = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._serve, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    _REASON = {200: "OK", 400: "Bad Request", 402: "Payment Required",
               404: "Not Found", 409: "Conflict"}

    async def _serve(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                request = await reader.readline()
                if not request:
                    break
                method, path, _ = request.decode().split(" ", 2)
                headers = {}
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    key, _, value = line.decode().partition(":")
                    headers[key.strip().lower()] = value.strip()
                body = await reader.readexactly(int(headers.get("content-length", 0)))
                code, extra, payload = await self._handler(method, path, headers, body)
                data = json.dumps(payload).encode()
                head = [f"HTTP/1.1 {code} {self._REASON.get(code, '')}",
                        "Content-Type: application/json",
                        f"Content-Length: {len(data)}"]
                head += [f"{k}: {v}" for k, v in (extra or {}).items()]
                writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + data)
                await writer.drain()
        except (ConnectionError, ValueError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()


class Facilitator:
    """The x402 facilitator endpoint: verify = Alg. 2, settle = Alg. 1 + 2."""

    def __init__(self, client: Client, host: str = "127.0.0.1", port: int = 0):
        self.client = client
        self._http = _HTTPServer(self._route, host, port)

    @property
    def port(self) -> int:
        return self._http.port

    async def start(self) -> None:
        await self._http.start()

    async def stop(self) -> None:
        await self._http.stop()

    async def verify(self, p: Payment) -> dict:
        status, evidence = self.client.view.settle_check(p)
        out = {"status": status.value}
        if status is SettleStatus.REJECTED:
            out["conflictProof"] = [pp.to_dict() for pp in evidence]
        return out

    async def settle(self, p: Payment, timeout_s: float = 5.0) -> dict:
        if not p.verify():
            return {"status": "invalid"}
        await self.client.write(p)
        status, evidence = await self.client.wait(p, timeout_s=timeout_s)
        out = {"status": status.value}
        if status is SettleStatus.SETTLED:
            out["certificate"] = evidence
            out["certificateHash"] = hashlib.sha256(
                json.dumps(evidence["C_p"], sort_keys=True).encode()).hexdigest()
        elif status is SettleStatus.REJECTED:
            out["conflictProof"] = [pp.to_dict() for pp in evidence]
        return out

    async def _route(self, method: str, path: str, headers: dict, body: bytes):
        if method != "POST" or path not in ("/verify", "/settle"):
            return 404, None, {"error": "not found"}
        try:
            p = Payment.from_dict(json.loads(body)["payment"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return 400, None, {"error": "malformed payment"}
        result = await (self.verify(p) if path == "/verify" else self.settle(p))
        code = {"settled": 200, "pending": 200, "invalid": 400,
                "insolvent": 402, "rejected": 409}[result["status"]]
        return code, None, result


class ResourceServer:
    """Demo x402 seller: quotes on 402, serves on settled payment."""

    def __init__(self, facilitator: Facilitator, payee: str, price: int,
                 resources: Optional[dict] = None,
                 host: str = "127.0.0.1", port: int = 0):
        self.facilitator = facilitator
        self.payee = payee
        self.price = price
        self.resources = resources or {"/resource": {"data": "premium bytes"}}
        self._http = _HTTPServer(self._route, host, port)

    @property
    def port(self) -> int:
        return self._http.port

    async def start(self) -> None:
        await self._http.start()

    async def stop(self) -> None:
        await self._http.stop()

    def quote(self, path: str) -> dict:
        q = {"payTo": self.payee, "maxAmountRequired": self.price,
             "resource": path, "scheme": "turnstile", "network": "pod"}
        q["quoteHash"] = hashlib.sha256(
            json.dumps(q, sort_keys=True).encode()).hexdigest()
        return q

    async def _route(self, method: str, path: str, headers: dict, body: bytes):
        if method != "GET" or path not in self.resources:
            return 404, None, {"error": "not found"}
        raw = headers.get("x-payment")
        if raw is None:
            return 402, None, {"accepts": [self.quote(path)]}
        try:
            p = Payment.from_dict(json.loads(raw))
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return 400, None, {"error": "malformed X-PAYMENT"}
        quote = self.quote(path)
        if p.m != quote["quoteHash"] or p.P != self.payee or p.v < self.price:
            return 402, None, {"error": "payment does not match quote",
                               "accepts": [quote]}
        result = await self.facilitator.settle(p)
        if result["status"] != "settled":
            return 402, None, {"error": f"settlement {result['status']}",
                               "accepts": [quote]}
        return 200, {"X-PAYMENT-RESPONSE": result["certificateHash"]}, \
            self.resources[path]
