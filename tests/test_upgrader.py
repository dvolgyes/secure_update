from datetime import date

from secure_update.models import Vulnerability, VulnerablePackage
from secure_update.upgrader import build_upgrade_args


def _pkg(
    name: str, version: str, vulns: list[tuple[str, list[str]]]
) -> VulnerablePackage:
    return VulnerablePackage(
        name=name,
        version=version,
        vulns=[Vulnerability(id=vid, fix_versions=fixes) for vid, fixes in vulns],
    )


def test_build_upgrade_args_basic() -> None:
    pkg = _pkg("urllib3", "2.4.0", [("CVE-A", ["2.6.0"]), ("CVE-B", ["2.6.3"])])
    assert build_upgrade_args([pkg]) == ["--upgrade-package", "urllib3>=2.6.3"]


def test_build_upgrade_args_with_exclude_newer() -> None:
    pkg = _pkg("urllib3", "2.4.0", [("CVE-A", ["2.6.3"])])
    args = build_upgrade_args([pkg], exclude_newer=date(2026, 3, 18))
    assert args == [
        "--upgrade-package",
        "urllib3>=2.6.3",
        "--exclude-newer",
        "2026-03-18",
    ]


def test_build_upgrade_args_multiple_packages() -> None:
    packages = [
        _pkg("requests", "2.28.0", [("CVE-R", ["2.32.0"])]),
        _pkg("certifi", "2023.1.0", [("CVE-C", ["2024.1.0"])]),
    ]
    args = build_upgrade_args(packages)
    assert args == [
        "--upgrade-package",
        "requests>=2.32.0",
        "--upgrade-package",
        "certifi>=2024.1.0",
    ]


def test_build_upgrade_args_skips_no_fix_version() -> None:
    pkg = _pkg("broken", "1.0.0", [("CVE-X", [])])
    assert build_upgrade_args([pkg]) == []


def test_build_upgrade_args_empty_input() -> None:
    assert build_upgrade_args([]) == []


def test_build_upgrade_args_no_exclude_newer() -> None:
    pkg = _pkg("flask", "3.0.0", [("CVE-F", ["3.1.0"])])
    args = build_upgrade_args([pkg], exclude_newer=None)
    assert "--exclude-newer" not in args
