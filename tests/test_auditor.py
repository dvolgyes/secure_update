from pathlib import Path
from typing import Any

from secure_update.auditor import parse_lock_versions, parse_vulnerabilities

FIXTURE_JSON: dict[str, Any] = {
    "files": [
        {
            "file_path": "uv.lock",
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "2.4.0",
                    "vulns": [
                        {"id": "GHSA-aaa", "fix_versions": ["2.6.0"]},
                        {"id": "GHSA-bbb", "fix_versions": ["2.6.3"]},
                    ],
                },
                {
                    "name": "requests",
                    "version": "2.28.0",
                    "vulns": [],
                },
                {
                    "name": "certifi",
                    "version": "2023.1.0",
                    "vulns": [
                        {"id": "GHSA-ccc", "fix_versions": []},
                    ],
                },
            ],
        }
    ]
}

FIXTURE_LOCK = Path(__file__).parent / "fixtures" / "m3l" / "uv.lock"


def test_parse_vulnerabilities_returns_only_vulnerable() -> None:
    result = parse_vulnerabilities(FIXTURE_JSON)
    names = [p.name for p in result]
    assert "urllib3" in names
    assert "certifi" in names
    assert "requests" not in names


def test_parse_vulnerabilities_maps_fields_correctly() -> None:
    result = parse_vulnerabilities(FIXTURE_JSON)
    urllib3 = next(p for p in result if p.name == "urllib3")
    assert urllib3.version == "2.4.0"
    assert len(urllib3.vulns) == 2
    assert urllib3.vulns[0].id == "GHSA-aaa"
    assert urllib3.vulns[1].fix_versions == ["2.6.3"]


def test_parse_vulnerabilities_empty_files() -> None:
    assert parse_vulnerabilities({"files": []}) == []


def test_parse_vulnerabilities_missing_files_key() -> None:
    assert parse_vulnerabilities({}) == []


def test_parse_lock_versions_finds_diskcache() -> None:
    versions = parse_lock_versions(FIXTURE_LOCK)
    assert "diskcache" in versions
    assert versions["diskcache"] == "5.6.3"


def test_parse_lock_versions_returns_dict_of_strings() -> None:
    versions = parse_lock_versions(FIXTURE_LOCK)
    assert isinstance(versions, dict)
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in versions.items())


def test_parse_lock_versions_has_many_packages() -> None:
    versions = parse_lock_versions(FIXTURE_LOCK)
    assert len(versions) > 50
