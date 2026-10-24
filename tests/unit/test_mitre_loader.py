from pathlib import Path

from argusloom.cti.mitre_loader import MITRELoader


def _loader() -> MITRELoader:
    fixture_dir = Path(__file__).resolve().parents[2] / "data" / "mitre"
    return MITRELoader(
        attack_path=fixture_dir / "attack.json",
        atlas_path=fixture_dir / "atlas.json",
    )


def test_mitre_loader_loads_attack_and_atlas_records() -> None:
    assert len(_loader().load_all()) >= 30


def test_mitre_loader_finds_lateral_technique_by_keyword() -> None:
    results = _loader().find_by_keyword("lateral")

    assert results
    assert any(technique.id == "T1021" for technique in results)


def test_mitre_loader_gets_technique_by_id() -> None:
    technique = _loader().get_by_id("T1190")

    assert technique is not None
    assert technique.name == "Exploit Public-Facing Application"
