from __future__ import annotations

import secrets
import struct
from dataclasses import dataclass, field

from pyroaring import BitMap

HEADER = struct.Struct(">32sBQI")
STAGE = {"activity": 1, "adjacency": 2}


def encode_block(epoch, stage, start, values):
    if any(type(v) is not int or not 0 <= v < 7 for v in values):
        raise ValueError("Invalid field value")
    return HEADER.pack(bytes.fromhex(epoch), STAGE[stage], start, len(values)) + bytes(values)


def decode_block(payload, epoch, stage, start, count):
    if not isinstance(payload, bytes) or len(payload) != HEADER.size + count:
        raise ValueError("Missing or truncated contribution")
    if HEADER.unpack_from(payload) != (bytes.fromhex(epoch), STAGE[stage], start, count):
        raise ValueError("Wrong session/stage/offset or duplicate block")
    values = payload[HEADER.size:]
    if any(v >= 7 for v in values):
        raise ValueError("Noncanonical field encoding")
    return values


def recover(payloads, epoch, stage, start, count):
    if len(payloads) != 6:
        raise ValueError("All six clients must contribute, including zero rows")
    total = [0] * count
    for payload in payloads:
        for i, value in enumerate(decode_block(payload, epoch, stage, start, count)):
            total[i] = (total[i] + value) % 7
    return total


def choose_candidates(n, active, schedule):
    if not active <= set(range(1, n + 1)):
        raise ValueError("Invalid activity support")
    capacity = next((c for c in schedule if len(active) < c <= n), n)
    padding = secrets.SystemRandom().sample(sorted(set(range(1, n + 1)) - active),
                                            capacity - len(active))
    return sorted(active | set(padding))


@dataclass(repr=False)
class PreparedGraph:
    epoch: str
    n: int
    candidates: list[int]
    neighborhoods: dict[int, BitMap] = field(default_factory=dict)
    degrees: dict[int, int] = field(default_factory=dict)
    coordinates: int = 0


async def aggregate(mpc, config, epoch, alignment, local_edges, keys, progress=None):
    report = progress if progress is not None else lambda *args: None
    n = alignment.n
    indexed_edges = set()
    active = set()
    if mpc.pid:
        mapping = alignment.local_to_index
        for u, v in local_edges:
            p, q = mapping[u], mapping[v]
            indexed_edges.update(((p, q), (q, p)))
            active.update((p, q))

    async def stage_blocks(stage, width, candidates):
        count = n if stage == "activity" else width * width
        report(stage, 0, count)
        for start in range(0, count, config["block_elements"]):
            size = min(config["block_elements"], count - start)
            payload = None
            if mpc.pid:
                values = []
                for offset in range(start, start + size):
                    if stage == "activity":
                        p, q = offset + 1, 0
                        value = int(p in active)
                    else:
                        p, q = candidates[offset // width], candidates[offset % width]
                        value = int((p, q) in indexed_edges)
                    values.append(keys.masked(mpc.pid, stage, p, q, value))
                payload = encode_block(epoch, stage, start, values)
            contributions = await mpc.transfer(payload, senders=list(range(1, 7)), receivers=[0])
            total = recover(contributions, epoch, stage, start, size) if mpc.pid == 0 else None
            yield start, total

            ack = await mpc.transfer((epoch, stage, start), senders=0)
            if ack != (epoch, stage, start):
                raise ValueError("Invalid block acknowledgement")
            report(stage, start + size, count)

    global_active = set()
    async for start, total in stage_blocks("activity", 0, []):
        if mpc.pid == 0:
            global_active.update(start + i + 1 for i, value in enumerate(total) if value)
    candidates = choose_candidates(n, global_active, config["candidate_capacities"]) if mpc.pid == 0 else None
    candidates = await mpc.transfer(candidates, senders=0)
    if (not isinstance(candidates, list) or candidates != sorted(set(candidates))
            or any(type(p) is not int or not 1 <= p <= n for p in candidates)):
        raise ValueError("Invalid candidate metadata")
    if mpc.pid and not active <= set(candidates):
        raise ValueError("Candidate set excludes a local endpoint")
    width = len(candidates)
    graph = PreparedGraph(epoch, n, candidates, coordinates=n + width * width)
    if mpc.pid == 0:
        graph.neighborhoods = {p: BitMap() for p in range(1, n + 1)}
    async for start, total in stage_blocks("adjacency", width, candidates):
        if mpc.pid == 0:
            for i, value in enumerate(total):
                offset = start + i
                p, q = candidates[offset // width], candidates[offset % width]
                if p == q and value:
                    raise ValueError("Nonzero diagonal: inconsistent masks or local input")
                if value and p != q:
                    graph.neighborhoods[p].add(q)
    if mpc.pid == 0:
        for p, neighbors in graph.neighborhoods.items():
            if any(p not in graph.neighborhoods[q] for q in neighbors):
                raise ValueError("Asymmetric recovered graph")
        graph.degrees = {p: len(row) for p, row in graph.neighborhoods.items()}
        if {p for p, d in graph.degrees.items() if d} != global_active:
            raise ValueError("Activity and adjacency support disagree")
    return graph
