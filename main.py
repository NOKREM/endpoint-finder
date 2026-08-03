"""Convenience launcher so ``python main.py <url>`` works from the repository root."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from endpoint_finder.main import main  # noqa: E402

if __name__ == "__main__":
    main()
