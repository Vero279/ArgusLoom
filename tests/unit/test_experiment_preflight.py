from pathlib import Path

from experiments.preflight import collect_preflight_blockers

ROOT = Path(__file__).resolve().parents[2]


def test_preflight_fails_closed_for_unapproved_inputs() -> None:
    blockers = collect_preflight_blockers(ROOT)

    assert "shared system prompt and template are not approved" in blockers
    assert "shared num_ctx has not been selected and frozen by the pilot" in blockers
    assert "CTI snapshot manifest is not marked ready" in blockers
    assert "source-derived 30-question gold set is missing" in blockers
