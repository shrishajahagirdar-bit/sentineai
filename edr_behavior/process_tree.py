from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class ProcessNode:
    pid: int
    name: str
    parent_pid: int | None = None
    children: set[int] = field(default_factory=set)


class ProcessTreeReconstructor:
    def __init__(self) -> None:
        self.host_trees: dict[str, dict[int, ProcessNode]] = defaultdict(dict)

    def ingest(self, event: dict) -> dict[str, object]:
        host = str(event.get("hostname") or event.get("host") or "unknown-host")
        pid = int(event.get("pid") or 0)
        if pid <= 0:
            return {"host": host, "pid": pid, "node_count": len(self.host_trees[host])}
        raw_data = event.get("raw_data") or event.get("parsed_fields") or {}
        if not isinstance(raw_data, dict):
            raw_data = {}
        parent_pid = raw_data.get("parent_pid")
        try:
            parent_pid_int = int(parent_pid) if parent_pid is not None else None
        except (TypeError, ValueError):
            parent_pid_int = None
        tree = self.host_trees[host]
        node = tree.get(pid)
        if node is None:
            node = ProcessNode(pid=pid, name=str(event.get("process_name") or "unknown"), parent_pid=parent_pid_int)
            tree[pid] = node
        else:
            node.name = str(event.get("process_name") or node.name)
            node.parent_pid = parent_pid_int
        if parent_pid_int:
            parent = tree.get(parent_pid_int)
            if parent is None:
                parent = ProcessNode(pid=parent_pid_int, name="unknown", parent_pid=None)
                tree[parent_pid_int] = parent
            parent.children.add(pid)
        return {
            "host": host,
            "pid": pid,
            "parent_pid": parent_pid_int,
            "children": sorted(tree[pid].children),
            "node_count": len(tree),
        }
