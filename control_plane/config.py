from __future__ import annotations

import os
from dataclasses import dataclass


def _csv_env(name: str, default: str) -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class ControlPlaneSettings:
    app_name: str = os.getenv("CONTROL_PLANE_APP_NAME", "SentinelAI Control Plane")
    database_url: str = os.getenv(
        "CONTROL_PLANE_DATABASE_URL",
        "postgresql+psycopg2://sentinelai:sentinelai@localhost:5432/sentinelai",
    )
    jwt_secret: str = os.getenv("CONTROL_PLANE_JWT_SECRET", "sentinelai-dev-secret")
    jwt_algorithm: str = os.getenv("CONTROL_PLANE_JWT_ALGORITHM", "HS256")
    access_token_minutes: int = int(os.getenv("CONTROL_PLANE_ACCESS_TOKEN_MINUTES", "30"))
    refresh_token_minutes: int = int(os.getenv("CONTROL_PLANE_REFRESH_TOKEN_MINUTES", "43200"))
    api_rate_limit_per_minute: int = int(os.getenv("CONTROL_PLANE_RATE_LIMIT_PER_MINUTE", "600"))
    allowed_roles: list[str] = None  # type: ignore[assignment]
    bootstrap_admin_email: str = os.getenv("CONTROL_PLANE_BOOTSTRAP_ADMIN_EMAIL", "admin@sentinelai.local")
    bootstrap_admin_password: str = os.getenv("CONTROL_PLANE_BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe123!")

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_roles", _csv_env("CONTROL_PLANE_ALLOWED_ROLES", "admin,analyst,viewer,system_operator"))


settings = ControlPlaneSettings()
