import argparse
import hashlib
import importlib.metadata
from pathlib import Path
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from fedcs_private.config import config_digest, read_json, validate_config


def check_role(role, dns=False):
    for package, expected in (("mpyc", "0.11"), ("cryptography", "46.0.3"), ("pyroaring", "1.0.4")):
        if importlib.metadata.version(package) != expected:
            raise ValueError(f"Install the pinned requirements: {package}=={expected}")
    role = Path(role).resolve()
    config = validate_config(read_json(role / "cluster.json"))
    pid = read_json(role / "role.json")["pid"]
    if type(pid) is not int or pid not in range(7):
        raise ValueError("Invalid role")
    tls = role / ".config"
    cert = x509.load_pem_x509_certificate((tls / f"party_{pid}.crt").read_bytes())
    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    if fingerprint != config["fingerprints"][pid]:
        raise ValueError("Role certificate does not match pinned fingerprint")
    now = datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("Certificate expired or not yet valid; check clock synchronization")
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate((tls / "mpyc_ca.crt").read_bytes()))
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(str(tls / "mpyc_ca.crt"))
    context.load_cert_chain(str(tls / f"party_{pid}.crt"), str(tls / f"party_{pid}.key"))
    if sorted(p.name for p in tls.glob("*.key")) != [f"party_{pid}.key"]:
        raise ValueError("Role directory contains another role's private key")
    if pid == 0 and (role / "secrets.json").exists():
        raise ValueError("Coordinator has client master secrets")
    if pid:
        from fedcs_private.crypto import SessionKeys
        SessionKeys.load(role / "secrets.json", pid, "preflight-only")
    if dns:
        for host, port in zip(config["hosts"], config["ports"]):
            socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return pid, config_digest(config)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path, required=True)
    parser.add_argument("--dns", action="store_true")
    args = parser.parse_args()
    pid, digest = check_role(args.deployment, args.dns)
    print(f"Preflight OK: role={pid}, public_config_sha256={digest}")
    print("This is not a firewall/connectivity test; real mutual-TLS connectivity is tested during start.")
