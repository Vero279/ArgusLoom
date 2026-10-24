"""Load curated MITRE ATT&CK and ATLAS techniques from local JSON fixtures."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class MITRETechnique:
    id: str
    name: str
    tactic: str
    description: str
    keywords: list[str]
    source: str


class MITRELoader:
    """Read technique fixtures once and provide deterministic keyword lookup."""

    def __init__(self, attack_path: Path, atlas_path: Path) -> None:
        self.attack_path = Path(attack_path)
        self.atlas_path = Path(atlas_path)
        self._techniques = self._load_file(
            self.attack_path, "attack"
        ) + self._load_file(self.atlas_path, "atlas")
        self._techniques.sort(key=lambda technique: (technique.id, technique.source))

    @staticmethod
    def _load_file(path: Path, source: str) -> list[MITRETechnique]:
        records: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return [
            MITRETechnique(
                id=str(record["id"]),
                name=str(record["name"]),
                tactic=str(record["tactic"]),
                description=str(record["description"]),
                keywords=[str(keyword) for keyword in record.get("keywords", [])],
                source=source,
            )
            for record in records
        ]

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return set(re.findall(r"[a-z0-9]+", value.casefold()))

    def load_all(self) -> list[MITRETechnique]:
        return list(self._techniques)

    def find_by_keyword(self, keyword: str) -> list[MITRETechnique]:
        query_tokens = self._tokens(keyword)
        if not query_tokens:
            return []

        matches = []
        for technique in self._techniques:
            searchable = " ".join(
                [technique.name, technique.description, *technique.keywords]
            )
            if query_tokens & self._tokens(searchable):
                matches.append(technique)
        return matches

    def get_by_id(self, technique_id: str) -> MITRETechnique | None:
        return next(
            (
                technique
                for technique in self._techniques
                if technique.id == technique_id
            ),
            None,
        )
