from __future__ import annotations


PLAN_LIMITS = {
    "free": {"events_per_second": 25, "api_calls_per_minute": 300, "ml_predictions_per_day": 10000},
    "pro": {"events_per_second": 500, "api_calls_per_minute": 3000, "ml_predictions_per_day": 500000},
    "enterprise": {"events_per_second": 5000, "api_calls_per_minute": 25000, "ml_predictions_per_day": 5000000},
}
