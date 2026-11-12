from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
from dataclasses import dataclass, field

from .config import config_digest, load_graph, read_json, validate_config
from .crypto import SessionKeys, new_epoch


@dataclass(repr=False)
class State:
    alignment: object
    graph: object
    timings: dict
    index: object = None
    local_tokens: dict = field(default_factory=dict)


async def prepare(mpc, config, role_dir, input_path, keep_connections=False, progress=None):
    from .alignment import align, align_sort_rank
    from .aggregation import aggregate

    report = progress if progress is not None else lambda *args: None
    report("setup")
    started = time.perf_counter()
    cpu_started = time.process_time()
    await mpc.start()
    digest = config_digest(config)
    agreements = await mpc.transfer(digest)
    if agreements != [digest] * 7:
        raise ValueError("Public protocol parameters disagree")
    nonces = await mpc.transfer(secrets.token_bytes(32))
    epoch = new_epoch(digest, nonces)
    keys = None
    vertices, edges, tokens = [], set(), []
    if mpc.pid:
        vertices, edges = load_graph(input_path, config["capacities"][mpc.pid - 1])
        keys = SessionKeys.load(role_dir / "secrets.json", mpc.pid, epoch)
        tokens = [keys.token(v, config["namespace"]) for v in vertices]
        if len(set(tokens)) != len(tokens):
            raise ValueError("Local token collision")

    commitment = hashlib.sha256(keys.identity + keys.blinding).digest() if keys else None
    commitments = await mpc.transfer(commitment, senders=list(range(1, 7)), receivers=list(range(1, 7)))
    if mpc.pid and len(set(commitments)) != 1:
        raise ValueError("Client identity/blinding keys disagree")
    for i in range(1, 7):
        for j in range(i + 1, 7):
            own = hashlib.sha256(keys.pairs[j if mpc.pid == i else i]).digest() if mpc.pid in (i, j) else None
            values = await mpc.transfer(own, senders=[i, j], receivers=[i, j])
            if mpc.pid in (i, j) and values[0] != values[1]:
                raise ValueError("Pairwise secrets disagree")
    aligned_start = time.perf_counter()
    report("alignment")
    aligner = align_sort_rank if config.get("alignment_backend") == "sort-rank-v1" else align
    alignment = await aligner(mpc, config["capacities"], vertices, tokens, progress=progress)
    alignment.epoch = epoch
    aligned_end = time.perf_counter()
    report("aggregation")
    graph = await aggregate(mpc, config, epoch, alignment, edges, keys, progress=progress)
    aggregated = time.perf_counter()
    index = None
    report("index")
    if mpc.pid == 0:
        from .index import build_index
        index = build_index(graph.neighborhoods, epoch)
    if await mpc.transfer(("INDEX_VALIDATED", epoch)) != [("INDEX_VALIDATED", epoch)] * 7:
        raise ValueError("Incomplete preparation")
    sent = sum(p.protocol.nbytes_sent for p in mpc.parties if p.pid != mpc.pid)
    if not keep_connections:
        await mpc.shutdown()
    finished = time.perf_counter()
    from .metrics import peak_rss_bytes
    width = len(graph.candidates)
    block_size = config["block_elements"]
    blocks = ((alignment.n + block_size - 1) // block_size
              + (width * width + block_size - 1) // block_size)
    return State(alignment, graph, {
        "setup_input_seconds": aligned_start - started,
        "alignment_seconds": aligned_end - aligned_start,
        "aggregation_finish_seconds": finished - aligned_end,
        "aggregation_seconds": aggregated - aligned_end,
        "index_barrier_seconds": finished - aggregated,
        "mpc_bytes_sent": sent,
        "aggregation_blocks_per_client": blocks,
        "aggregation_field_bytes_per_client": graph.coordinates,
        "cpu_seconds": time.process_time() - cpu_started,
        "peak_rss_bytes": peak_rss_bytes(),
        "wall_seconds": finished - started,
    }, index, dict(zip(vertices, tokens)))


def main(default_pid=None, check=None):
    parser = argparse.ArgumentParser(description="Private graph and RAM-only GCT preparation")
    parser.add_argument("--deployment", type=Path, required=True, help="This role's provisioned directory")
    parser.add_argument("--input", type=Path, help="Local declared-vertices/edges TXT or JSON, clients only")
    parser.add_argument("--exit-after-build", action="store_true", help="Testing only: discard in-memory state on exit")
    parser.add_argument("--progress", action="store_true", help="Emit public stage/circuit counters only")
    args = parser.parse_args()
    role_dir = args.deployment.resolve()
    from network_check import check_role
    check_role(role_dir)
    config = validate_config(read_json(role_dir / "cluster.json"))
    pid = read_json(role_dir / "role.json")["pid"]
    if type(pid) is not int or pid not in range(7) or (default_pid is not None and pid != default_pid):
        raise ValueError("Wrong role directory")
    if pid == 0 and (args.input or (role_dir / "secrets.json").exists()):
        raise ValueError("Coordinator must not receive local graphs or client secrets")
    default_input = role_dir / ("input.txt" if (role_dir / "input.txt").exists() else "input.json")
    input_path = (args.input.resolve() if args.input else default_input) if pid else None

    sys.argv = [sys.argv[0], "-I", str(pid), "-T", "1", "--ssl", "--no-log",
                "--sec-param", "64", "--no-numpy"]
    for host, port in zip(config["hosts"], config["ports"]):
        sys.argv += ["-P", f"{host}:{port}"]
    os.chdir(role_dir)
    from mpyc.runtime import mpc
    from .transport import install_peer_pinning
    install_peer_pinning(mpc, config["fingerprints"])
    from .progress import Progress
    progress = Progress(pid) if args.progress else None

    async def execute():
        state = await asyncio.wait_for(prepare(mpc, config, role_dir, input_path,
                                              keep_connections=not args.exit_after_build, progress=progress),
                                       timeout=config["timeout_seconds"])
        if check:
            check(pid, config, role_dir, state)
        service = None
        if not args.exit_after_build:
            if progress:
                progress("publication")
            from .query import QueryService
            service = QueryService(pid, config, role_dir, state)
            try:
                await service.start()
                async def commit():
                    if await mpc.transfer(("QUERY_BOUND", state.graph.epoch)) != [("QUERY_BOUND", state.graph.epoch)] * 7:
                        raise ValueError("Incomplete query publication")
                    await mpc.shutdown()
                await asyncio.wait_for(commit(), timeout=60)
                service.ready = True
            except BaseException:
                await service.close()
                raise
        summary = {"status": "INDEX_READY" if args.exit_after_build else "QUERY_READY", "pid": pid, "epoch": state.graph.epoch,
                   "n": state.graph.n, "candidate_count": len(state.graph.candidates),
                   "coordinates": state.graph.coordinates, "timings": state.timings}
        if pid == 0:
            summary["edges"] = sum(state.graph.degrees.values()) // 2
            summary["gct_nodes"] = len(state.index.nodes) - 1
            summary["max_core"] = max(state.index.core)
        print(json.dumps(summary, sort_keys=True), flush=True)
        if not args.exit_after_build:
            try:
                await asyncio.Event().wait()
            finally:
                await service.close()

    try:
        mpc.run(execute())
    except KeyboardInterrupt:
        return
    except Exception as exc:

        print(json.dumps({"status": "ABORTED", "pid": pid, "error_type": type(exc).__name__}),
              file=sys.stderr, flush=True)
        raise SystemExit(1) from None
