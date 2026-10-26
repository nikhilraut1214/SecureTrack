"""Benchmark SecureTrack detection on dense failed-login episodes.

This script measures the current detector only. The Stage 1 audit baseline is
printed for comparison; it was measured on the same machine before the rewrite
and is not regenerated because the original implementation is no longer present.
"""

from __future__ import annotations

import statistics
import sys
import time
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.detection import detect_suspicious_activity  # noqa: E402

BASE = pd.Timestamp("2026-10-24T10:00:00Z")
SIZES = (1_000, 3_000, 6_000, 10_000, 50_000)
AUDIT_BASELINE = {
    1_000: 3.14,
    3_000: 34.71,
    6_000: 137.34,
    10_000: None,
    50_000: None,
}


def dense_frame(count: int) -> pd.DataFrame:
    """One IP/account with `count` failures inside a 100-second span."""
    offsets = [index % 100 for index in range(count)]
    return pd.DataFrame(
        {
            "timestamp": BASE + pd.to_timedelta(offsets, unit="s"),
            "username": ["user"] * count,
            "ip_address": ["192.0.2.9"] * count,
            "status": ["FAILED"] * count,
            "source_row": range(2, count + 2),
        }
    )


def main() -> None:
    print("SecureTrack detection benchmark (dense single-episode data)")
    print(f"pandas {pd.__version__} | Python {sys.version.split()[0]}")
    print()
    print(
        f"{'events':>7} {'median (s)':>12} {'min (s)':>10} {'max (s)':>10} "
        f"{'alerts':>7} {'evidence':>9} {'audit (s)':>10}"
    )

    for count in SIZES:
        frame = dense_frame(count)
        runs: list[float] = []
        alerts = []
        for _ in range(3):
            start = time.perf_counter()
            alerts = detect_suspicious_activity(frame, 5, 2)
            runs.append(time.perf_counter() - start)

        evidence_rows = len(alerts[0]["evidence"]) if alerts else 0
        baseline = AUDIT_BASELINE[count]
        baseline_text = f"{baseline:.2f}" if baseline is not None else "n/a"
        print(
            f"{count:>7,} {statistics.median(runs):>12.4f} "
            f"{min(runs):>10.4f} {max(runs):>10.4f} "
            f"{len(alerts):>7} {evidence_rows:>9,} {baseline_text:>10}"
        )

    print()
    print("Audit baseline is the pre-rewrite measurement recorded in")
    print("REPOSITORY_AUDIT.md. The 10,000-event original was not measured.")


if __name__ == "__main__":
    main()
