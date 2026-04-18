from __future__ import annotations

from fastapi import FastAPI, Response
from pydantic import BaseModel

from observability.metrics import export_prometheus, SERVICE_HEALTH
from pipeline.stream_processor import StreamProcessor


class EventRequest(BaseModel):
    event: dict
    persist: bool = True


app = FastAPI(title="SentinelAI Stream Processor", version="0.1.0")
processor = StreamProcessor()


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "stream-processor", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    SERVICE_HEALTH.labels(service="stream-processor").set(1)
    return {"service": "stream-processor", "status": "healthy"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(content=export_prometheus(), media_type="text/plain; version=0.0.4")


@app.post("/process")
def process(payload: EventRequest) -> dict:
    return processor.process_event(payload.event, persist=payload.persist)
