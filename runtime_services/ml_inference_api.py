from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

from ml_engine.inference import LiveModelEngine
from observability.metrics import export_prometheus, SERVICE_HEALTH
from fastapi import Response


class InferenceRequest(BaseModel):
    event: dict


app = FastAPI(title="SentinelAI ML Inference Service", version="0.1.0")
engine = LiveModelEngine()


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "ml-inference", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str]:
    SERVICE_HEALTH.labels(service="ml-inference").set(1)
    return {"service": "ml-inference", "status": "healthy"}


@app.get("/metrics")
def metrics() -> Response:
    return Response(content=export_prometheus(), media_type="text/plain; version=0.0.4")


@app.post("/infer")
def infer(payload: InferenceRequest) -> dict:
    return engine.predict_output(payload.event)
