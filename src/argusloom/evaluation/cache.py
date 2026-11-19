"""Content-addressed, append-by-rewrite cache for reproducible model runs."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class CacheIdentity:
    model_id: str
    model_digest: str
    question_id: str
    question_hash: str
    corpus_hash: str
    prompt_hash: str
    retrieval_hash: str
    decoding_hash: str
    seed: int
    run_type: str
    sample_index: int = 0

    def key(self) -> str:
        return hashlib.sha256(_canonical_json(asdict(self)).encode("utf-8")).hexdigest()


class ResultCache:
    """Cache records by model/input hashes; scenario names are only references."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise ValueError(
                            f"Invalid cache JSON on line {line_number}"
                        ) from exc
                    key = record.get("cache_key")
                    identity = record.get("identity")
                    if not isinstance(key, str) or not isinstance(identity, dict):
                        raise TypeError(f"Invalid cache record on line {line_number}")
                    if key != self._identity_key(identity):
                        raise ValueError(
                            f"Cache identity hash mismatch on line {line_number}"
                        )
                    self._records[key] = record

    @staticmethod
    def _identity_key(identity: dict[str, Any]) -> str:
        return hashlib.sha256(_canonical_json(identity).encode("utf-8")).hexdigest()

    def get(self, identity: CacheIdentity) -> dict[str, Any] | None:
        entry = self._records.get(identity.key())
        if entry is None:
            return None
        return dict(entry["result"])

    def get_or_generate(
        self,
        identity: CacheIdentity,
        scenario: str,
        generate: Callable[[], dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        existing = self._records.get(identity.key())
        if existing is not None:
            scenarios = list(existing.get("scenarios", []))
            if scenario not in scenarios:
                scenarios.append(scenario)
                existing["scenarios"] = scenarios
                self._write()
            return dict(existing["result"]), True

        result = generate()
        if not isinstance(result, dict):
            raise TypeError("experiment generator must return a dictionary")
        self._records[identity.key()] = {
            "cache_key": identity.key(),
            "identity": asdict(identity),
            "scenarios": [scenario],
            "result": result,
        }
        self._write()
        return dict(result), False

    def _write(self) -> None:
        temporary_path = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
            for key in sorted(self._records):
                handle.write(_canonical_json(self._records[key]))
                handle.write("\n")
        os.replace(temporary_path, self.path)
