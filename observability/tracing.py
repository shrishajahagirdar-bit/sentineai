from __future__ import annotations

try:
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
except ImportError:  # pragma: no cover
    trace = None
    TracerProvider = None


def configure_tracing(service_name: str) -> None:
    if trace is None or TracerProvider is None:
        return
    provider = TracerProvider()
    trace.set_tracer_provider(provider)


def tracer(name: str):
    if trace is None:
        return None
    return trace.get_tracer(name)
