from __future__ import annotations

import json

from ml_engine.training import train_models
from risk_engine.ueba import UebaEngine


def main() -> None:
    metadata = train_models()
    UebaEngine().rebuild()
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
