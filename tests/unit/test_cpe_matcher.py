from argusloom.cti.cpe_matcher import (
    CPEProductMapping,
    SoftwareIdentity,
    cpe_name_for_version,
    cpe_version_matches,
    match_cve_to_inventory,
    parse_cpe23_name,
)


def _mapping(
    software: str,
    part: str,
    vendor: str,
    product: str,
    *,
    verified: bool = True,
    required_version_components: int | None = None,
) -> CPEProductMapping:
    if required_version_components is None:
        required_version_components = {
            "postgresql": 2,
            "nginx": 3,
            "python": 3,
        }.get(software, 0)
    return CPEProductMapping(
        software_key=software,
        part=part,
        vendor=vendor,
        product=product,
        verified=verified,
        required_version_components=required_version_components,
    )


def test_cpe_name_parser_and_exact_candidate_builder() -> None:
    name = parse_cpe23_name("cpe:2.3:a:example:postgresql:14.10:*:*:*:*:*:*:*")

    assert (name.part, name.vendor, name.product, name.version) == (
        "a",
        "example",
        "postgresql",
        "14.10",
    )
    assert cpe_name_for_version(name, "15.5") == (
        "cpe:2.3:a:example:postgresql:15.5:*:*:*:*:*:*:*"
    )


def test_version_ranges_support_inclusive_exclusive_and_exact_versions() -> None:
    assert cpe_version_matches(
        "*",
        "14.10",
        version_start_including="14.0",
        version_end_excluding="15.0",
    )
    assert not cpe_version_matches(
        "*",
        "15.0",
        version_start_including="14.0",
        version_end_excluding="15.0",
    )
    assert cpe_version_matches("15.5", "15.5")
    assert not cpe_version_matches("15.5", "15.6")
    assert not cpe_version_matches(
        "*",
        "15.0",
        version_end_including="15.0",
        version_end_excluding="15.0",
    )
    assert cpe_version_matches(
        "*",
        "15.0",
        version_start_excluding="14.10",
        version_end_including="15.0",
    )
    assert not cpe_version_matches(
        "*",
        "14.10",
        version_start_excluding="14.10",
    )


def test_matcher_requires_resolved_and_and_non_vulnerable_running_on_terms() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "14.10",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*",
                            },
                        ],
                    }
                ]
            }
        ]
    }
    mappings = [
        _mapping("postgresql", "a", "postgresql", "postgresql"),
        _mapping("ubuntu", "o", "canonical", "ubuntu_linux"),
    ]

    assert match_cve_to_inventory(
        cve,
        [
            SoftwareIdentity("postgresql", "14.10"),
            SoftwareIdentity("ubuntu", "22.04"),
        ],
        mappings,
    )
    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("postgresql", "14.10")],
        mappings,
    )


def test_or_and_negation_are_resolved_without_false_positive() -> None:
    cve = {
        "configurations": [
            {
                "operator": "OR",
                "nodes": [
                    {
                        "operator": "AND",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.20.0",
                                "versionEndExcluding": "1.25.0",
                            }
                        ],
                        "negate": True,
                    },
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:1.26.0:*:*:*:*:*:*:*",
                            }
                        ],
                    },
                ],
            }
        ]
    }
    mapping = [_mapping("nginx", "a", "nginx", "nginx")]

    assert match_cve_to_inventory(cve, [SoftwareIdentity("nginx", "1.26.0")], mapping)
    assert not match_cve_to_inventory(
        cve, [SoftwareIdentity("nginx", "1.24.0")], mapping
    )


def test_unverified_mapping_and_unsupported_version_syntax_never_match() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "1.30.0-beta",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("nginx", "1.24.0")],
        [_mapping("nginx", "a", "nginx", "nginx", verified=False)],
    )
    assert (
        cpe_version_matches(
            "*",
            "1.24.0",
            version_end_including="1.30.0-beta",
        )
        is None
    )


def test_empty_declared_version_never_matches() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "")],
        [_mapping("python", "a", "python", "python")],
    )


def test_partial_declared_versions_never_match_patch_level_ranges() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "3.11.5",
                            }
                        ]
                    }
                ]
            }
        ]
    }
    mapping = [_mapping("python", "a", "python", "python")]

    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "3.11")],
        mapping,
    )
    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "python3.11")],
        mapping,
    )


def test_unknown_product_never_matches() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:python:unknown:*:*:*:*:*:*:*:*",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "3.11.5")],
        [_mapping("python", "a", "python", "python")],
    )


def test_complete_declared_version_matches_patch_level_range() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "3.11.5",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "3.11.5")],
        [_mapping("python", "a", "python", "python")],
    )


def test_complete_declared_version_outside_patch_level_range_never_matches() -> None:
    cve = {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
                                "versionEndIncluding": "3.11.5",
                            }
                        ]
                    }
                ]
            }
        ]
    }

    assert not match_cve_to_inventory(
        cve,
        [SoftwareIdentity("python", "3.12.0")],
        [_mapping("python", "a", "python", "python")],
    )
