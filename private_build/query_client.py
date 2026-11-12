import argparse
import asyncio
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from fedcs_private.config import read_json, validate_config
from fedcs_private.query import rpc
from network_check import check_role


async def query(role, vertices, k):
    pid, _ = check_role(role)
    if pid == 0:
        raise ValueError("Use a client role, not coordinator credentials")
    config = validate_config(read_json(role / "cluster.json"))
    status = await rpc(role, pid, config, pid, {"op": "status"}, host="127.0.0.1")
    if status.get("status") != "QUERY_READY":
        raise ValueError("Snapshot not published")
    return await rpc(role, pid, config, pid,
                     {"op": "query", "epoch": status["epoch"], "nodes": vertices, "k": k}, host="127.0.0.1")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--nodes", type=int, nargs="+", required=True)
    parser.add_argument("--k", type=int, required=True)
    args = parser.parse_args()
    try:
        result = asyncio.run(query(args.deployment.resolve(), args.nodes, args.k))
    except Exception as exc:
        print(json.dumps({"status": "REJECTED", "error_type": type(exc).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result))
    if result.get("status") != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
