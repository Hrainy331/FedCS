from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import PROTOCOL

MAX_ALIGNMENT_SLOTS = 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_config(config):
    expected = {"protocol", "hosts", "ports", "capacities", "candidate_capacities",
                "prime", "token_bits", "threshold", "statistical_security",
                "block_elements", "timeout_seconds", "namespace", "fingerprints"}
    optional = {"alignment_backend", "query_ports"}
    if not expected <= set(config) or set(config) - expected - optional or config["protocol"] != PROTOCOL:
        raise ValueError("Unsupported protocol or configuration fields")
    if (config["prime"], config["token_bits"], config["threshold"],
            config["statistical_security"]) != (7, 256, 1, 64):
        raise ValueError("This version locks P=7, 256-bit tokens, t=1, statistical security=64")
    hosts, ports = config["hosts"], config["ports"]
    if len(hosts) != 7 or len(ports) != 7:
        raise ValueError("Exactly one coordinator and six clients required")
    if any(not isinstance(h, str) or not h or ":" in h or any(c.isspace() for c in h)
           for h in hosts):
        raise ValueError("Use IPv4 addresses or DNS names, without schemes or port suffixes")
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports):
        raise ValueError("Invalid TCP port")
    if len(set(zip(hosts, ports))) != 7:
        raise ValueError("Role endpoints must be distinct")
    caps = config["capacities"]
    if len(caps) != 6 or any(type(b) is not int or b < 1 for b in caps):
        raise ValueError("Six positive public input capacities required")
    backend = config.get("alignment_backend", "reference-v1")
    if backend not in ("reference-v1", "sort-rank-v1"):
        raise ValueError("Unsupported private alignment backend")
    limit = MAX_ALIGNMENT_SLOTS if backend == "reference-v1" else 262144
    if sum(caps) > limit:
        raise ValueError("Public capacity exceeds the selected circuit's resource guard")
    query_ports = config.get("query_ports", [p + 100 for p in ports])
    if (len(query_ports) != 7 or any(type(p) is not int or not 1024 <= p <= 65535 for p in query_ports)
            or len(set(zip(hosts, ports)) | set(zip(hosts, query_ports))) != 14):
        raise ValueError("Query endpoints must be distinct from all build endpoints")
    schedule = config["candidate_capacities"]
    if (any(type(x) is not int or x < 1 for x in schedule)
            or schedule != sorted(set(schedule))):
        raise ValueError("Candidate capacities must be positive, increasing and distinct")
    if type(config["block_elements"]) is not int or not 1 <= config["block_elements"] <= 65536:
        raise ValueError("Invalid block size")
    max_timeout = 86400 if backend == "reference-v1" else 2592000
    if type(config["timeout_seconds"]) is not int or not 10 <= config["timeout_seconds"] <= max_timeout:
        raise ValueError("Invalid whole-preparation timeout")
    if not isinstance(config["namespace"], str) or not config["namespace"]:
        raise ValueError("An explicit vertex namespace is required")
    fps = config["fingerprints"]
    if (len(fps) != 7 or len(set(fps)) != 7
            or any(not isinstance(x, str) or len(x) != 64
                   or any(c not in "0123456789abcdef" for c in x) for x in fps)):
        raise ValueError("Seven distinct SHA-256 certificate fingerprints required")
    return config


def config_digest(config):
    return hashlib.sha256(canonical(validate_config(config))).hexdigest()


def load_graph(path, capacity):

    if Path(path).suffix.lower() == ".txt":
        from .local_text import read_local_text
        raw = read_local_text(path)
    else:
        raw = read_json(path)
    if not isinstance(raw, dict) or set(raw) != {"vertices", "edges"}:
        raise ValueError("Input must contain vertices and edges only")
    vertices = raw["vertices"]
    if not isinstance(vertices, list) or any(type(x) is not int for x in vertices):
        raise ValueError("Vertices must be integer IDs (not booleans or strings)")
    vertices = sorted(set(vertices))
    if len(vertices) > capacity:
        raise ValueError("Local input exceeds public capacity; no automatic capacity disclosure")
    declared = set(vertices)
    edges = set()
    if not isinstance(raw["edges"], list):
        raise ValueError("Edges must be a list")
    for edge in raw["edges"]:
        if (not isinstance(edge, list) or len(edge) != 2
                or any(type(x) is not int or x not in declared for x in edge)):
            raise ValueError("Every edge endpoint must be a declared integer vertex")
        u, v = edge
        if u != v:
            edges.add((min(u, v), max(u, v)))
    return vertices, edges
