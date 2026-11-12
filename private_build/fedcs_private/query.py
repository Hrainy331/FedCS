import asyncio
import hashlib
import json
import ssl
import struct
import time
from pathlib import Path

MAX_FRAME = 16 * 1024 * 1024
MAX_QUERY = 4096


def tls_context(role, pid, server=False):
    role = Path(role) / ".config"
    purpose = ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(str(role / "mpyc_ca.crt"))
    context.load_cert_chain(str(role / f"party_{pid}.crt"), str(role / f"party_{pid}.key"))
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def peer_id(writer, config):
    tls = writer.get_extra_info("ssl_object")
    if tls is None:
        raise ValueError("TLS required")
    fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
    try:
        return config["fingerprints"].index(fingerprint)
    except ValueError:
        raise ValueError("Unpinned peer") from None


async def read_frame(reader):
    size = struct.unpack(">I", await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("Invalid frame size")
    value = json.loads(await reader.readexactly(size))
    if not isinstance(value, dict):
        raise ValueError("Object required")
    return value


async def write_frame(writer, value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    if not 0 < len(payload) <= MAX_FRAME:
        raise ValueError("Response exceeds frame budget")
    writer.write(struct.pack(">I", len(payload)) + payload)
    await writer.drain()


async def rpc(role, pid, config, target, request, host=None, timeout=30):
    async def exchange():
        ports = config.get("query_ports", [p + 100 for p in config["ports"]])
        reader, writer = await asyncio.open_connection(
            host or config["hosts"][target], ports[target], ssl=tls_context(role, pid),
            server_hostname=f"MPyC party {target}", ssl_handshake_timeout=10)
        try:
            if peer_id(writer, config) != target:
                raise ValueError("Wrong server role")
            await write_frame(writer, request)
            return await read_frame(reader)
        finally:
            writer.close()
            await writer.wait_closed()
    return await asyncio.wait_for(exchange(), timeout)


class QueryService:
    def __init__(self, pid, config, role, state):
        self.pid, self.config, self.role, self.state = pid, config, role, state
        self.ready = False
        self.server = None
        self.sequence = 0
        self.seen = {i: 0 for i in range(1, 7)}
        self.lock = asyncio.Lock()
        self.connections = set()
        self.local_inverse = {i: v for v, i in state.alignment.local_to_index.items()}

    async def start(self):
        self.validate_state()
        ports = self.config.get("query_ports", [p + 100 for p in self.config["ports"]])


        self.server = await asyncio.start_server(
            self.handle, "0.0.0.0" if self.pid == 0 else "127.0.0.1", ports[self.pid],
            ssl=tls_context(self.role, self.pid, server=True), ssl_handshake_timeout=10)

    def validate_state(self):
        state, n = self.state, self.state.graph.n
        if state.alignment.epoch != state.graph.epoch or state.alignment.n != n:
            raise ValueError("Stale alignment epoch or dimension")
        if self.pid == 0:
            from .index import validate_index
            if (state.index is None or state.index.epoch != state.graph.epoch
                    or state.alignment.local_to_index or state.local_tokens
                    or set(state.alignment.token_to_index.values()) != set(range(1, n + 1))
                    or len(state.alignment.token_to_index) != n or len(state.graph.neighborhoods) != n):
                raise ValueError("Incomplete or cross-role server state")
            if state.graph.degrees != {v: len(row) for v, row in state.graph.neighborhoods.items()}:
                raise ValueError("Stale graph degrees")
            validate_index(state.index, state.graph.neighborhoods)
        elif (state.index is not None or state.alignment.token_to_index or state.graph.neighborhoods
              or state.graph.degrees or set(state.local_tokens) != set(state.alignment.local_to_index)
              or any(not 1 <= i <= n for i in state.alignment.local_to_index.values())):
            raise ValueError("Incomplete or cross-role client state")

    async def close(self):
        self.ready = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for writer in list(self.connections):
            writer.close()

    async def handle(self, reader, writer):
        if len(self.connections) >= 16:
            writer.close()
            return
        self.connections.add(writer)
        try:
            peer = peer_id(writer, self.config)
            if (self.pid == 0 and peer not in range(1, 7)) or (self.pid and peer != self.pid):
                raise ValueError("Unauthorized role")
            request = await asyncio.wait_for(read_frame(reader), 10)
            response = await asyncio.wait_for(self.dispatch(peer, request), 30)
            await asyncio.wait_for(write_frame(writer, response), 10)
        except Exception:

            try:
                await asyncio.wait_for(write_frame(writer, {"status": "REJECTED"}), 2)
            except Exception:
                pass
        finally:
            self.connections.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def dispatch(self, peer, request):
        if (self.pid == 0 and peer not in range(1, 7)) or (self.pid and peer != self.pid):
            raise ValueError("Unauthorized role")
        if not self.ready:
            return {"status": "NOT_READY"}
        epoch = self.state.graph.epoch
        if request == {"op": "status"}:
            return {"status": "QUERY_READY", "epoch": epoch, "n": self.state.graph.n}
        fields = {"op", "epoch", "sequence", "k", "tokens"} if self.pid == 0 else {"op", "epoch", "k", "nodes"}
        if set(request) != fields or request["op"] != "query" or request["epoch"] != epoch:
            raise ValueError("Invalid query envelope")
        k = request["k"]
        if type(k) is not int or not 0 <= k <= 2**31 - 1:
            raise ValueError("Invalid threshold")
        if self.pid == 0:
            if peer not in self.seen:
                raise ValueError("Unauthorized query requester")
            sequence, tokens = request["sequence"], request["tokens"]
            if (type(sequence) is not int or sequence <= self.seen[peer] or sequence > 2**63 - 1
                    or not isinstance(tokens, list) or not 1 <= len(tokens) <= MAX_QUERY
                    or any(not isinstance(t, str) or len(t) != 64
                           or any(c not in "0123456789abcdef" for c in t) for t in tokens)):
                raise ValueError("Invalid query or replay")
            self.seen[peer] = sequence
            indices = [self.state.alignment.token_to_index.get(int(t, 16), 0) for t in tokens]
            started = time.perf_counter()
            result = self.state.index.query(indices, k)
            return {"status": "OK", "epoch": epoch, "sequence": sequence, "indices": result,
                    "search_seconds": time.perf_counter() - started}
        if peer != self.pid:
            raise ValueError("Local gateway requires this role's certificate")
        vertices = request["nodes"]
        if (not isinstance(vertices, list) or not 1 <= len(vertices) <= MAX_QUERY
                or any(type(v) is not int or v not in self.state.local_tokens for v in vertices)):
            raise ValueError("Query vertices must belong to this client's local mapping")
        async with self.lock:
            self.sequence += 1
            start = time.perf_counter()
            envelope = {"op": "query", "epoch": epoch, "sequence": self.sequence, "k": k,
                        "tokens": [f"{self.state.local_tokens[v]:064x}" for v in vertices]}
            result = await rpc(self.role, self.pid, self.config, 0, envelope)
            if (result.get("status") != "OK" or result.get("epoch") != epoch
                    or result.get("sequence") != self.sequence):
                raise ValueError("Stale or rejected server response")
            indices = result["indices"]
            if (not isinstance(indices, list) or len(indices) != len(set(indices))
                    or any(type(i) is not int or not 1 <= i <= self.state.graph.n for i in indices)):
                raise ValueError("Invalid result indices")

            members = [{"index": i, **({"id": self.local_inverse[i]} if i in self.local_inverse else {})}
                       for i in indices]
            return {"status": "OK", "epoch": epoch, "size": len(indices), "members": members,
                    "search_seconds": result["search_seconds"],
                    "query_application_bytes": 8 + sum(len(json.dumps(value, separators=(",", ":")).encode())
                                                       for value in (envelope, result)),
                    "online_seconds": time.perf_counter() - start}
