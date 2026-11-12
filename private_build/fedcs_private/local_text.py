from pathlib import Path

MAGIC = "# fedcs-local-v1"


def read_local_text(path):
    vertices, edges = [], []
    with Path(path).open(encoding="utf-8-sig") as handle:
        if handle.readline().strip() != MAGIC:
            raise ValueError("Expected fedcs-local-v1 TXT header")
        for line in handle:
            parts = line.split()
            if not parts or parts[0].startswith("#"):
                continue
            if parts[0] == "v" and len(parts) == 2:
                vertices.append(int(parts[1]))
            elif parts[0] == "e" and len(parts) == 3:
                edges.append([int(parts[1]), int(parts[2])])
            else:
                raise ValueError("Invalid local TXT record")
    return {"vertices": vertices, "edges": edges}


def write_local_text(path, vertices, edges):
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(MAGIC + "\n")
        for v in sorted(vertices):
            handle.write(f"v {v}\n")
        for u, v in sorted(edges):
            handle.write(f"e {u} {v}\n")
