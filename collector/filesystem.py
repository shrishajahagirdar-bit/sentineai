from __future__ import annotations

from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Any

from sentinel_config import CONFIG

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover
    FileSystemEventHandler = object
    Observer = None


class _QueueHandler(FileSystemEventHandler):
    def __init__(self, queue: Queue) -> None:
        super().__init__()
        self.queue = queue

    def on_created(self, event: Any) -> None:
        self._push("file_created", event)

    def on_modified(self, event: Any) -> None:
        self._push("file_modified", event)

    def on_deleted(self, event: Any) -> None:
        self._push("file_deleted", event)

    def _push(self, event_type: str, event: Any) -> None:
        if getattr(event, "is_directory", False):
            return
        self.queue.put(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "file_monitor",
                "event_type": event_type,
                "status": "ok",
                "path": getattr(event, "src_path", ""),
                "sensitive_file_access": self._is_sensitive(getattr(event, "src_path", "")),
                "user": "system",
                "message": f"{event_type.replace('_', ' ').title()}: {getattr(event, 'src_path', '')}",
            }
        )

    @staticmethod
    def _is_sensitive(path: str) -> bool:
        lowered = path.lower()
        return any(keyword in lowered for keyword in CONFIG.sensitive_path_keywords)


class FileActivityCollector:
    def __init__(self) -> None:
        self.queue: Queue = Queue()
        self.observer = None
        self.enabled = False

    def start(self) -> list[dict[str, Any]]:
        if Observer is None:
            return [self._status_event("warning", "watchdog is not installed; file activity monitoring is unavailable.")]

        if self.enabled:
            return []

        self.observer = Observer()
        handler = _QueueHandler(self.queue)
        scheduled = 0

        for directory in CONFIG.monitor_directories:
            try:
                if directory.exists():
                    self.observer.schedule(handler, str(directory), recursive=True)
                    scheduled += 1
            except Exception:
                continue

        if scheduled == 0:
            return [self._status_event("warning", "No monitor directories were available for file watching.")]

        self.observer.daemon = True
        self.observer.start()
        self.enabled = True
        return [self._status_event("ok", f"File activity monitoring enabled for {scheduled} directories.")]

    def collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        while True:
            try:
                events.append(self.queue.get_nowait())
            except Empty:
                break
        return events

    def stop(self) -> None:
        if self.observer is not None:
            self.observer.stop()
            self.observer.join(timeout=3)
        self.enabled = False

    @staticmethod
    def _status_event(level: str, message: str) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "file_monitor",
            "event_type": "collector_status",
            "status": level,
            "message": message,
            "user": "system",
        }

