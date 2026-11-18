"""Normalise verified LM-Polygraph method statistics for experiment records."""

from __future__ import annotations

import math
import re
from collections.abc import Callable
from typing import Any

VERBALIZED_CONFIDENCE_PATTERN = re.compile(
    r'"confidence"\s*:\s*(-?(?:\d+(?:\.\d+)?|\.\d+))',
    flags=re.IGNORECASE,
)

METHOD_STATISTICS = {
    "verbalized_uncertainty_1s": "greedy_texts",
    "lexsim": "sample_texts",
    "msp": "greedy_log_likelihoods",
    "mte": "entropy",
}


def verbalized_uncertainty(text: str) -> tuple[float, str | None]:
    """Return one-minus-confidence, or NaN with a parse-failure reason."""

    match = VERBALIZED_CONFIDENCE_PATTERN.search(text)
    if match is None:
        return math.nan, "confidence_not_found"
    confidence = float(match.group(1))
    if not 0.0 <= confidence <= 1.0:
        return math.nan, "confidence_out_of_range"
    return 1.0 - confidence, None


def require_method_statistic(method: str, stats: dict[str, Any]) -> Any:
    """Fetch the statistic required by the verified method contract."""

    statistic = METHOD_STATISTICS.get(method)
    if statistic is None:
        raise ValueError(f"Unsupported uncertainty method '{method}'")
    if statistic not in stats:
        raise ValueError(
            f"LM-Polygraph statistic '{statistic}' is missing for method '{method}'"
        )
    return stats[statistic]


class LMPolygraphAdapter:
    """Bind verified method statistics to an LM-Polygraph 0.7.0 score callback."""

    def __init__(
        self,
        estimator: Callable[[str, Any], float] | None = None,
    ) -> None:
        self.estimator = estimator

    def score(
        self,
        method: str,
        stats: dict[str, Any] | None = None,
        *,
        greedy_text: str | None = None,
    ) -> tuple[float, str | None]:
        if method == "verbalized_uncertainty_1s":
            if greedy_text is None:
                return math.nan, "greedy_text_missing"
            return verbalized_uncertainty(greedy_text)
        if stats is None:
            raise ValueError(f"LM-Polygraph statistics are required for '{method}'")
        statistic = require_method_statistic(method, stats)
        if self.estimator is None:
            raise RuntimeError(
                f"LM-Polygraph estimator callback is required for '{method}'"
            )
        value = self.estimator(method, statistic)
        if type(value) not in (int, float):
            raise TypeError("LM-Polygraph estimator must return a numeric score")
        return float(value), None if math.isfinite(float(value)) else "nan_score"
