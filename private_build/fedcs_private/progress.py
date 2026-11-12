import json
import math
import sys
import time

STAGES = frozenset(("setup", "alignment", "alignment_input", "sort_tokens", "mark_unique",
                    "prefix_ranks", "compact_input", "sort_union", "return_input",
                    "sort_slots", "return_ranks", "aggregation", "activity", "adjacency",
                    "index", "publication"))


def validate_progress(value, pid):
    if (not isinstance(value, dict)
            or set(value) != {"status", "pid", "stage", "completed", "total", "elapsed_seconds"}
            or value["status"] != "PROGRESS" or type(value["pid"]) is not int
            or value["pid"] != pid or pid not in range(7)
            or not isinstance(value["stage"], str) or value["stage"] not in STAGES
            or type(value["completed"]) is not int or type(value["total"]) is not int
            or not 0 <= value["completed"] <= value["total"] <= 2**63 - 1
            or type(value["elapsed_seconds"]) not in (int, float)
            or not math.isfinite(value["elapsed_seconds"]) or value["elapsed_seconds"] < 0):
        raise ValueError("Invalid public progress record")
    return dict(value)


class Progress:
    def __init__(self, pid, interval=30, stream=None):
        self.pid, self.interval = pid, interval
        self.stream = stream if stream is not None else sys.stdout
        self.started = time.monotonic()
        self.previous_stage, self.previous_time = None, self.started

    def __call__(self, stage, completed=0, total=1):
        now = time.monotonic()
        value = validate_progress({"status": "PROGRESS", "pid": self.pid, "stage": stage,
                                   "completed": completed, "total": total,
                                   "elapsed_seconds": now - self.started}, self.pid)
        if stage != self.previous_stage or completed == total or now - self.previous_time >= self.interval:
            print(json.dumps(value, sort_keys=True), file=self.stream, flush=True)
            self.previous_stage, self.previous_time = stage, now
