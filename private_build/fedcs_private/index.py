from dataclasses import dataclass, field


def core_numbers(adjacency):

    n = len(adjacency)
    if set(adjacency) != set(range(1, n + 1)):
        raise ValueError("Expected contiguous global indices")
    degree = [0] + [len(adjacency[v]) for v in range(1, n + 1)]
    bins = [0] * (max(degree) + 1)
    for v in range(1, n + 1):
        if v in adjacency[v] or any(u not in adjacency or v not in adjacency[u]
                                    for u in adjacency[v]):
            raise ValueError("Expected a simple undirected graph")
        bins[degree[v]] += 1
    start = 0
    for d, size in enumerate(bins):
        bins[d], start = start, start + size
    vertices, position = [0] * n, [0] * (n + 1)
    for v in range(1, n + 1):
        position[v] = bins[degree[v]]
        vertices[position[v]] = v
        bins[degree[v]] += 1
    for d in range(len(bins) - 1, 0, -1):
        bins[d] = bins[d - 1]
    bins[0] = 0
    for v in vertices:
        for u in adjacency[v]:
            if degree[u] > degree[v]:
                d, pu = degree[u], position[u]
                pw = bins[d]
                w = vertices[pw]
                vertices[pu], vertices[pw] = w, u
                position[u], position[w] = pw, pu
                bins[d] += 1
                degree[u] -= 1
    return degree


@dataclass(repr=False)
class Node:
    level: int
    payload: list = field(default_factory=list)
    children: list = field(default_factory=list)
    parent: int = 0


@dataclass(repr=False)
class GCT:
    core: list
    nodes: list
    owner: list
    order: list
    position: list
    begin: list
    end: list
    up: list
    epoch: str = ""

    def query(self, indices, k):
        if type(k) is not int or k < 0 or not isinstance(indices, (list, tuple)) or not indices:
            raise ValueError("A nonempty query and a nonnegative integer k are required")
        if any(type(p) is not int or not 1 <= p < len(self.core) for p in indices):
            return []
        if any(self.core[p] < k for p in indices):
            return []
        anchor = self.owner[indices[0]]
        for table in reversed(self.up):
            parent = table[anchor]
            if parent and self.nodes[parent].level >= k:
                anchor = parent
        lo, hi = self.begin[anchor], self.end[anchor]
        if any(not lo <= self.position[p] < hi for p in indices):
            return []
        return self.order[lo:hi]


def build_index(adjacency, epoch=""):
    core = core_numbers(adjacency)
    n = len(adjacency)
    buckets = {}
    for v in range(1, n + 1):
        buckets.setdefault(core[v], []).append(v)
    parent, size = list(range(n + 1)), [1] * (n + 1)
    active = [False] * (n + 1)

    head, tail = [0] * (n + 1), [0] * (n + 1)
    nodes, next_node = [Node(-1)], [0]
    owner = [0] * (n + 1)

    def find(v):
        while parent[v] != v:
            parent[v] = parent[parent[v]]
            v = parent[v]
        return v

    def union(a, b):
        a, b = find(a), find(b)
        if a == b:
            return
        if size[a] < size[b]:
            a, b = b, a
        parent[b], size[a] = a, size[a] + size[b]
        if head[b]:
            if head[a]:
                next_node[tail[a]] = head[b]
            else:
                head[a] = head[b]
            tail[a] = tail[b]
        head[b] = tail[b] = 0

    for level in sorted(buckets, reverse=True):
        batch = buckets[level]
        for v in batch:
            active[v] = True
        for v in batch:
            for u in adjacency[v]:
                if active[u]:
                    union(v, u)
        payloads = {}
        for v in batch:
            payloads.setdefault(find(v), []).append(v)
        for root, payload in payloads.items():
            node_id = len(nodes)
            children, child = [], head[root]
            while child:
                children.append(child)
                nodes[child].parent = node_id
                child = next_node[child]
            nodes.append(Node(level, payload, children))
            next_node.append(0)
            head[root] = tail[root] = node_id
            for v in payload:
                owner[v] = node_id
    nodes[0].children = [head[v] for v in range(1, n + 1) if find(v) == v]
    order, position = [], [0] * (n + 1)
    begin, end = [0] * len(nodes), [0] * len(nodes)
    stack = [(0, False)]
    while stack:
        node_id, leaving = stack.pop()
        if leaving:
            end[node_id] = len(order)
            continue
        begin[node_id] = len(order)
        for v in nodes[node_id].payload:
            position[v] = len(order)
            order.append(v)
        stack.append((node_id, True))
        stack.extend((child, False) for child in reversed(nodes[node_id].children))
    up = [[node.parent for node in nodes]]
    for _ in range(1, len(nodes).bit_length()):
        previous = up[-1]
        up.append([previous[previous[v]] for v in range(len(nodes))])
    if sorted(order) != list(range(1, n + 1)) or len(nodes) > n + 1:
        raise ValueError("Incomplete GCT payload partition")
    for i, node in enumerate(nodes[1:], 1):
        if not node.payload or nodes[node.parent].level >= node.level:
            raise ValueError("Invalid GCT hierarchy")
        if not begin[node.parent] <= begin[i] < end[i] <= end[node.parent]:
            raise ValueError("Invalid GCT intervals")
    result = GCT(core, nodes, owner, order, position, begin, end, up, epoch)
    validate_index(result, adjacency)
    return result


def validate_index(index, adjacency):

    n, t = len(adjacency), len(index.nodes)
    if (len(index.core) != n + 1 or len(index.owner) != n + 1 or len(index.position) != n + 1
            or len(index.begin) != t or len(index.end) != t or not index.up
            or len(index.up) != t.bit_length() or any(len(row) != t for row in index.up)
            or sorted(index.order) != list(range(1, n + 1))):
        raise ValueError("Incomplete index tables")
    if index.core != core_numbers(adjacency):
        raise ValueError("Core table does not match graph")
    if not t or index.nodes[0].level != -1 or index.nodes[0].payload or index.nodes[0].parent != 0:
        raise ValueError("Invalid virtual root")
    seen, visited = set(), set()
    stack = [(0, False)]
    cursor = 0
    while stack:
        i, leaving = stack.pop()
        if leaving:
            if index.end[i] != cursor:
                raise ValueError("Wrong subtree interval")
            continue
        if i in visited or not 0 <= i < t:
            raise ValueError("Cycle or missing GCT node")
        visited.add(i)
        node = index.nodes[i]
        if index.begin[i] != cursor:
            raise ValueError("Wrong subtree start")
        if i and (not node.payload or index.nodes[node.parent].level >= node.level):
            raise ValueError("Invalid level or empty payload")
        for v in node.payload:
            if (v in seen or not 1 <= v <= n or index.owner[v] != i or index.core[v] != node.level
                    or index.position[v] != cursor or index.order[cursor] != v):
                raise ValueError("Payload mapping inconsistent")
            seen.add(v)
            cursor += 1
        stack.append((i, True))
        for child in reversed(node.children):
            if not 1 <= child < t or index.nodes[child].parent != i:
                raise ValueError("Broken parent link")
            stack.append((child, False))
    if len(visited) != t or len(seen) != n:
        raise ValueError("Unreachable GCT payload")
    if index.up[0] != [node.parent for node in index.nodes]:
        raise ValueError("Broken ancestor base table")
    for previous, current in zip(index.up, index.up[1:]):
        if current != [previous[previous[i]] for i in range(t)]:
            raise ValueError("Broken ancestor table")
