# FedCS

## Introduction
This repository provides **only a simple example using the Slashdot dataset** for **Global Community Search over Graph Federation**, not a complete multi-dataset experimental suite.
FedCS combines private vertex alignment and deduplicated graph aggregation with a compact Global Core Tree (GCT).
For a query Q = (A, k), it retrieves the connected component of the global k-core containing every vertex in A, or an empty result if no such component exists.

## Datasets
We include a processed Slashdot network from [SNAP](https://snap.stanford.edu/data/), split across six clients, with 51,083 vertices and 116,573 distinct undirected edges in the union.
The six input files are stored at `/srv/FedCS/private_build/client1/slashdot.txt` through `/srv/FedCS/private_build/client6/slashdot.txt` after installation; the split manifest records their checksums.

Each TXT file declares vertices, including isolated vertices, and edges:
```text
# fedcs-local-v1
v 1
v 2
v 3
e 1 2
```

## Algorithms
The implementation uses Python and consists of the following modules under `/srv/FedCS/private_build/fedcs_private/`.

1. **crypto.py**: Session-key derivation, HMAC-SHA256 vertex tokens, multiplicative blinding, and pairwise masks.
2. **alignment.py**: Private vertex alignment using seven-party MPyC.
3. **aggregation.py**: Blockwise masked aggregation over the field modulo 7 that deduplicates overlapping edges.
4. **index.py**: Core decomposition, compact GCT construction, and community search.
5. **query.py**: Authenticated TLS query services and local result resolution.
6. **transport.py**: Certificate fingerprint checks for the TLS-protected build connections.
7. **runtime.py**: Orchestration of token generation, alignment, aggregation, in-memory index construction, and query-service startup.

The build pipeline is: local graphs -> HMAC tokens -> private alignment -> masked graph aggregation -> GCT -> online queries.
HMAC tokens are pseudonyms, not reversible encryption. Pairwise masks cancel during aggregation; the coordinator learns the deduplicated topology under global indices and builds and searches the GCT on that topology. TLS encrypts network traffic; this is not encrypted-domain GCT search.

Index maintenance is outside this implementation.

## Usage
The following example uses a trusted Linux provisioning machine with the project at `/srv/FedCS`, one coordinator (`10.20.0.10`), and six Linux clients (`10.20.0.11`–`10.20.0.16`); replace these example addresses and use an existing SSH account named `fedcs` on each host.

1. **Install dependencies on the trusted machine** after copying the project to `/srv/FedCS` (Ubuntu 24.04 example).
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv openssh-client
python3 -m venv /srv/FedCS/.venv
/srv/FedCS/.venv/bin/python -m pip install -r /srv/FedCS/private_build/requirements.txt
```

2. **Generate fresh role-specific credentials** for the retained Slashdot inputs; the output directory must not already exist.
```bash
/srv/FedCS/.venv/bin/python -B /srv/FedCS/private_build/provision.py \
  --output /srv/FedCS/private_build/deployments/linux01 \
  --hosts 10.20.0.10 10.20.0.11 10.20.0.12 10.20.0.13 10.20.0.14 10.20.0.15 10.20.0.16 \
  --capacities 32768 8192 32768 128 16384 16384 \
  --alignment-backend sort-rank-v1 --block-elements 65536 \
  --base-port 16400 --query-base-port 16500 --timeout 2592000
```

3. **Distribute only each host's code, role credentials, and local input**, never the complete deployment directory or other clients' data.
```bash
for pid in {0..6}; do
  host="10.20.0.$((10 + pid))"
  role="client${pid}"
  if [ "$pid" -eq 0 ]; then role=coordinator; fi
  ssh "fedcs@$host" "mkdir -p /home/fedcs/FedCS/private_build/$role /home/fedcs/FedCS/private_build/deployments"
  scp -r /srv/FedCS/private_build/fedcs_private "fedcs@$host:/home/fedcs/FedCS/private_build/"
  scp /srv/FedCS/private_build/{requirements.txt,network_check.py,query_client.py} "fedcs@$host:/home/fedcs/FedCS/private_build/"
  scp "/srv/FedCS/private_build/$role/run.py" "fedcs@$host:/home/fedcs/FedCS/private_build/$role/"
  scp -r "/srv/FedCS/private_build/deployments/linux01/$role" "fedcs@$host:/home/fedcs/FedCS/private_build/deployments/"
  if [ "$pid" -gt 0 ]; then
    scp "/srv/FedCS/private_build/$role/slashdot.txt" "fedcs@$host:/home/fedcs/FedCS/private_build/$role/"
  fi
  ssh "fedcs@$host" 'chmod -R go-rwx /home/fedcs/FedCS'
done
```

4. **Install dependencies and check each role** after an administrator installs `python3` and `python3-venv` on all seven hosts.
```bash
for pid in {0..6}; do
  host="10.20.0.$((10 + pid))"
  role="client${pid}"
  if [ "$pid" -eq 0 ]; then role=coordinator; fi
  ssh "fedcs@$host" "python3 -m venv /home/fedcs/FedCS/.venv && \
    /home/fedcs/FedCS/.venv/bin/python -m pip install -r /home/fedcs/FedCS/private_build/requirements.txt && \
    /home/fedcs/FedCS/.venv/bin/python -B /home/fedcs/FedCS/private_build/network_check.py \
    --deployment /home/fedcs/FedCS/private_build/deployments/$role --dns"
done
```

5. **Start the coordinator in a dedicated terminal** after allowing cluster-only TCP traffic to client build ports 16401–16406 and coordinator query port 16500; client query ports 16501–16506 remain loopback-only.
```bash
ssh -t fedcs@10.20.0.10 '/home/fedcs/FedCS/.venv/bin/python -B /home/fedcs/FedCS/private_build/coordinator/run.py --deployment /home/fedcs/FedCS/private_build/deployments/coordinator --progress'
```

6. **Start each client in another dedicated terminal**, repeating this command with `pid=1` through `pid=6` and supplying the retained input explicitly.
```bash
pid=1
ssh -t "fedcs@10.20.0.$((10 + pid))" "/home/fedcs/FedCS/.venv/bin/python -B /home/fedcs/FedCS/private_build/client${pid}/run.py --deployment /home/fedcs/FedCS/private_build/deployments/client${pid} --input /home/fedcs/FedCS/private_build/client${pid}/slashdot.txt --progress"
```

7. **Submit a query on client 1 after all seven roles report `QUERY_READY`**, using a nonempty set of its local vertex IDs and a nonnegative k (this example selects its first local vertex).
```bash
ssh fedcs@10.20.0.11
node=$(awk '$1 == "v" {print $2; exit}' /home/fedcs/FedCS/private_build/client1/slashdot.txt)
/home/fedcs/FedCS/.venv/bin/python -B /home/fedcs/FedCS/private_build/query_client.py \
  --deployment /home/fedcs/FedCS/private_build/deployments/client1 --nodes "$node" --k 2
```

Results contain global member indices and original IDs only for vertices known locally.
Keep all role processes running; Ctrl+C stops them and discards their RAM state, so restarting requires rebuilding.
Full Slashdot private construction has not yet been validated end to end and may be expensive; `sort-rank-v1` remains experimental.
This research prototype reveals protected-ID global topology to the coordinator and is not an oblivious-query system or an independently audited production service.

## Requirements
+ Linux with Python 3.11+ (Ubuntu 24.04 recommended)
+ MPyC 0.11
+ cryptography 46.0.3
+ pyroaring 1.0.4
+ Bash, OpenSSH, synchronized clocks, and private network connectivity among all seven roles