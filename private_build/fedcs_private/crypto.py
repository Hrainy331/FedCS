from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from .config import canonical, read_json


def derive(master, purpose, epoch):
    return hmac.digest(master, canonical(["fedcs-private-small-v1", purpose, epoch]), "sha256")


def field_prf(key, label, coordinates, nonzero=False):

    bound = 6 if nonzero else 7
    limit = 256 - 256 % bound
    prefix = canonical([label, list(coordinates)])
    counter = 0
    while True:
        stream = hmac.digest(key, prefix + struct.pack(">Q", counter), "sha256")
        for byte in stream:
            if byte < limit:
                return byte % bound + int(nonzero)
        counter += 1


@dataclass(repr=False)
class SessionKeys:
    identity: bytes
    blinding: bytes
    pairs: dict[int, bytes]

    @classmethod
    def load(cls, path, pid, epoch):
        raw = read_json(path)
        if pid not in range(1, 7) or set(raw) != {"identity", "blinding", "pairs"}:
            raise ValueError("Invalid client secret file")
        if set(raw["pairs"]) != {str(i) for i in range(1, 7) if i != pid}:
            raise ValueError("A client must hold only its five incident pair secrets")
        identity = bytes.fromhex(raw["identity"])
        blind = bytes.fromhex(raw["blinding"])
        pairs = {int(i): bytes.fromhex(k) for i, k in raw["pairs"].items()}
        all_keys = [identity, blind, *pairs.values()]
        if any(len(k) != 32 for k in all_keys) or len(set(all_keys)) != 7:
            raise ValueError("Independent 256-bit master secrets required")
        return cls(derive(identity, "identity", epoch), derive(blind, "blind", epoch),
                   {i: derive(k, "pair", epoch) for i, k in pairs.items()})

    def token(self, vertex, namespace):
        message = canonical(["vertex", namespace, "integer", str(vertex)])
        return int.from_bytes(hmac.digest(self.identity, message, "sha256"), "big")

    def masked(self, pid, stage, p, q, value):
        if value not in (0, 1) or stage not in ("activity", "adjacency"):
            raise ValueError("Invalid aggregation input")
        if stage == "activity":
            r = field_prf(self.blinding, "actb", (p,), nonzero=True)
        else:
            r = 1 if p == q else field_prf(
                self.blinding, "blind", (min(p, q), max(p, q)), nonzero=True)
        result = r * value
        for peer, key in self.pairs.items():
            mask = field_prf(key, "actm" if stage == "activity" else "adj", (p, q))
            result += mask if peer > pid else -mask
        return result % 7


def new_epoch(config_hash, nonces):
    if len(nonces) != 7 or any(not isinstance(n, bytes) or len(n) != 32 for n in nonces):
        raise ValueError("Seven fresh session nonces required")
    return hashlib.sha256(bytes.fromhex(config_hash) + b"".join(nonces)).hexdigest()
