from dataclasses import dataclass, field


@dataclass(repr=False)
class Alignment:
    n: int
    token_to_index: dict[int, int] = field(default_factory=dict)
    local_to_index: dict[int, int] = field(default_factory=dict)
    epoch: str = ""


async def align(mpc, capacities, local_vertices, local_tokens, progress=None):
    secint = mpc.SecInt(258)
    sentinel = (1 << 256) + 1
    private_inputs = {}
    encoded = []
    for owner, capacity in enumerate(capacities, 1):
        values = []
        for slot in range(capacity):
            valid = mpc.pid == owner and slot < len(local_tokens)
            values.extend((secint(local_tokens[slot] if valid else 0), secint(int(valid))))
        shared = mpc.input(values, senders=owner)
        private_inputs[owner] = list(zip(shared[::2], shared[1::2]))
        encoded.extend(valid * (token + 1) + (1 - valid) * sentinel
                       for token, valid in private_inputs[owner])

    ordered = mpc.sorted(encoded)
    distinct = [ordered[0]]
    distinct.extend(mpc.if_else(ordered[i] != ordered[i - 1], ordered[i], secint(sentinel))
                    for i in range(1, len(ordered)))
    compact = mpc.sorted(distinct)
    n = int(await mpc.output(mpc.sum([x != sentinel for x in compact]), receivers=list(range(7))))

    revealed = await mpc.output(compact, receivers=[0])
    result = Alignment(n)
    if mpc.pid == 0:
        if revealed[n:] != [sentinel] * (len(compact) - n):
            raise ValueError("Invalid compacted union")
        result.token_to_index = {int(t) - 1: i + 1 for i, t in enumerate(revealed[:n])}
        if len(result.token_to_index) != n:
            raise ValueError("Non-distinct union")


    for owner, slots in private_inputs.items():
        indices = [valid * mpc.sum([(token + 1 == compact[j]) * (j + 1) for j in range(n)])
                   for token, valid in slots] if n else [secint(0) for _ in slots]
        opened = await mpc.output(indices, receivers=[owner])
        if mpc.pid == owner:
            local_indices = [int(x) for x in opened[:len(local_vertices)]]
            if any(not 1 <= x <= n for x in local_indices):
                raise ValueError("Private lookup failed")
            if any(opened[len(local_vertices):]):
                raise ValueError("Invalid padding output")
            result.local_to_index = dict(zip(local_vertices, local_indices))
    return result


def comparison_count(n):

    if n < 2:
        return 0
    total = 0
    p = 1 << ((n - 1).bit_length() - 1)
    while p:
        d, q, r = p, 1 << ((n - 1).bit_length() - 1), 0
        while d:
            end = n - d
            total += end // (2 * p) * p + max(0, min(p, end % (2 * p) - r))
            d, q, r = q - p, q >> 1, p
        p >>= 1
    return total


async def align_sort_rank(mpc, capacities, local_vertices, local_tokens, batch=256, progress=None):

    report = progress if progress is not None else lambda *args: None
    report("alignment_input", 0, sum(capacities))
    secint = mpc.SecInt(258)
    sentinel = (1 << 256) + 1
    rows, slot = [], 0
    for owner, capacity in enumerate(capacities, 1):
        for start in range(0, capacity, batch):
            values = []
            count = min(batch, capacity - start)
            for i in range(start, start + count):
                valid = mpc.pid == owner and i < len(local_tokens)
                values.extend((secint(local_tokens[i] if valid else 0), secint(int(valid))))
            shared = mpc.input(values, senders=owner)
            for token, valid in zip(shared[::2], shared[1::2]):
                rows.append([valid * (token + 1) + (1 - valid) * sentinel, secint(slot)])
                slot += 1
            await mpc.gather([x for row in rows[-count:] for x in row])
            report("alignment_input", slot, sum(capacities))

    async def sort(records, stage):

        n = len(records)
        total, completed = comparison_count(n), 0
        report(stage, completed, total)
        p = 1 << ((n - 1).bit_length() - 1)
        while p:
            d, q, r = p, 1 << ((n - 1).bit_length() - 1), 0
            while d:
                pending = []
                for i in range(n - d):
                    if i & p == r:
                        a, b = records[i], records[i + d]
                        records[i], records[i + d] = mpc.if_swap(a[0] < b[0], b, a)
                        pending.extend(records[i] + records[i + d])
                        if len(pending) >= batch * len(a) * 2:
                            await mpc.gather(pending)
                            completed += len(pending) // (len(a) * 2)
                            report(stage, completed, total)
                            pending.clear()
                if pending:
                    await mpc.gather(pending)
                    completed += len(pending) // (len(a) * 2)
                    report(stage, completed, total)
                d, q, r = q - p, q >> 1, p
            p >>= 1
        return records

    rows = await sort(rows, "sort_tokens")
    fresh, valid = [], []
    for start in range(0, slot, batch):
        for i in range(start, min(slot, start + batch)):
            valid.append(rows[i][0] != sentinel)
            fresh.append(valid[i] if i == 0 else valid[i] * (rows[i][0] != rows[i - 1][0]))
        await mpc.gather(fresh[start:] + valid[start:])
        report("mark_unique", min(slot, start + batch), slot)
    ranks = list(fresh)
    stride = 1
    while stride < slot:
        previous = ranks
        ranks = previous[:stride]
        for start in range(stride, slot, batch):
            current = [previous[i] + previous[i - stride]
                       for i in range(start, min(slot, start + batch))]
            await mpc.gather(current)
            ranks.extend(current)
        stride *= 2
        report("prefix_ranks", min(stride, slot), slot)
    n = int(await mpc.output(ranks[-1]))
    compact = []
    for start in range(0, slot, batch):
        values = [mpc.if_else(fresh[i], rows[i][0], secint(sentinel))
                  for i in range(start, min(slot, start + batch))]
        await mpc.gather(values)
        compact.extend([v] for v in values)
        report("compact_input", min(slot, start + batch), slot)
    compact = await sort(compact, "sort_union")
    result = Alignment(n)
    revealed = await mpc.output([row[0] for row in compact], receivers=[0])
    if mpc.pid == 0:
        if revealed[n:] != [sentinel] * (slot - n):
            raise ValueError("Invalid union compaction")
        result.token_to_index = {int(t) - 1: i + 1 for i, t in enumerate(revealed[:n])}
        if len(result.token_to_index) != n:
            raise ValueError("Non-distinct union")
    returned = []
    for start in range(0, slot, batch):
        values = [valid[i] * ranks[i] for i in range(start, min(slot, start + batch))]
        await mpc.gather(values)
        returned.extend([rows[start + j][1], v] for j, v in enumerate(values))
        report("return_input", min(slot, start + batch), slot)
    returned = await sort(returned, "sort_slots")
    start = 0
    for owner, capacity in enumerate(capacities, 1):
        indices = await mpc.output([row[1] for row in returned[start:start + capacity]], receivers=[owner])
        if mpc.pid == owner:
            local = [int(i) for i in indices[:len(local_vertices)]]
            if any(not 1 <= i <= n for i in local) or any(indices[len(local_vertices):]):
                raise ValueError("Invalid private rank output")
            result.local_to_index = dict(zip(local_vertices, local))
        start += capacity
        report("return_ranks", start, slot)
    return result
