from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from fedcs_private import PROTOCOL
from fedcs_private.config import validate_config

def role_name(pid):
    return "coordinator" if pid == 0 else f"client{pid}"


def write_private(path, data):

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def write_json(path, value):
    write_private(path, (json.dumps(value, indent=2) + "\n").encode())


def provision(output, hosts, base_port=16400, capacities=None, timeout=600,
              alignment_backend="reference-v1", block_elements=32, query_base_port=None):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError("Output directory already exists; refuse to overwrite keys or input")
    capacities = [4] * 6 if capacities is None else capacities
    config = {
        "protocol": PROTOCOL, "hosts": hosts, "ports": list(range(base_port, base_port + 7)),
        "capacities": capacities, "candidate_capacities": [4, 8, 16, 32, 64],
        "prime": 7, "token_bits": 256, "threshold": 1, "statistical_security": 64,
        "block_elements": 32, "timeout_seconds": timeout, "namespace": "fedcs-integer-vertices-v1",
        "fingerprints": [hashlib.sha256(bytes([i])).hexdigest() for i in range(7)],
    }
    config["alignment_backend"] = alignment_backend
    query_base_port = base_port + 100 if query_base_port is None else query_base_port
    config["query_ports"] = list(range(query_base_port, query_base_port + 7))
    config["block_elements"] = block_elements
    validate_config(config)
    output.mkdir(parents=True, mode=0o700)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FedCS Private Build CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    identity, blinding = secrets.token_hex(32), secrets.token_hex(32)
    pair_keys = {(i, j): secrets.token_hex(32) for i in range(1, 7) for j in range(i + 1, 7)}
    fingerprints = []
    for pid in range(7):
        role = output / role_name(pid)
        tls_dir = role / ".config"
        tls_dir.mkdir(parents=True, mode=0o700)
        os.chmod(role, 0o700)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"MPyC party {pid}")])
        names = [x509.DNSName(f"MPyC party {pid}")]
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(hosts[pid])))
        except ValueError:
            names.append(x509.DNSName(hosts[pid]))
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,
                                                    ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                .sign(ca_key, hashes.SHA256()))
        fingerprints.append(cert.fingerprint(hashes.SHA256()).hex())
        write_private(tls_dir / "mpyc_ca.crt", ca.public_bytes(serialization.Encoding.PEM))
        write_private(tls_dir / f"party_{pid}.crt", cert.public_bytes(serialization.Encoding.PEM))
        write_private(tls_dir / f"party_{pid}.key", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        write_json(role / "role.json", {"pid": pid})
        if pid:
            pairs = {str(j if pid == i else i): k for (i, j), k in pair_keys.items() if pid in (i, j)}
            write_json(role / "secrets.json", {"identity": identity, "blinding": blinding, "pairs": pairs})
    config["fingerprints"] = fingerprints
    validate_config(config)
    for pid in range(7):
        write_json(output / role_name(pid) / "cluster.json", config)

    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--hosts", nargs=7, default=["127.0.0.1"] * 7,
                        metavar="HOST", help="coordinator, then clients 1..6; IPv4/DNS")
    parser.add_argument("--base-port", type=int, default=16400)
    parser.add_argument("--capacities", nargs=6, type=int, default=[4] * 6)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--alignment-backend", choices=["reference-v1", "sort-rank-v1"], default="reference-v1")
    parser.add_argument("--block-elements", type=int, default=32)
    parser.add_argument("--query-base-port", type=int)
    args = parser.parse_args()
    output = provision(args.output, args.hosts, args.base_port, args.capacities, args.timeout,
                       args.alignment_backend, args.block_elements, args.query_base_port)
    print(f"Provisioned: {output}")
    print("Distribute ONLY the corresponding role directory; never send the whole root to any party.")
    print("Windows: restrict each directory ACL to its service account before real deployment.")


if __name__ == "__main__":
    main()
