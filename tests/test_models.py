from secure_update.models import Vulnerability, VulnerablePackage


def test_highest_fix_version_selects_max() -> None:
    pkg = VulnerablePackage(
        name="urllib3",
        version="2.0.0",
        vulns=[
            Vulnerability(id="CVE-A", fix_versions=["2.6.0"]),
            Vulnerability(id="CVE-B", fix_versions=["2.6.0"]),
            Vulnerability(id="CVE-C", fix_versions=["2.6.3"]),
        ],
    )
    assert pkg.highest_fix_version() == "2.6.3"


def test_highest_fix_version_no_fixes() -> None:
    pkg = VulnerablePackage(
        name="foo",
        version="1.0.0",
        vulns=[Vulnerability(id="CVE-X", fix_versions=[])],
    )
    assert pkg.highest_fix_version() is None


def test_highest_fix_version_single_vuln_multiple_fixes() -> None:
    pkg = VulnerablePackage(
        name="bar",
        version="1.0.0",
        vulns=[Vulnerability(id="CVE-Y", fix_versions=["1.2.0", "1.3.0"])],
    )
    assert pkg.highest_fix_version() == "1.3.0"


def test_highest_fix_version_no_vulns() -> None:
    pkg = VulnerablePackage(name="baz", version="1.0.0", vulns=[])
    assert pkg.highest_fix_version() is None
