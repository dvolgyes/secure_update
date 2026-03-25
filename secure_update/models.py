from dataclasses import dataclass, field

from packaging.version import Version


@dataclass(frozen=True)
class Vulnerability:
    id: str
    fix_versions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerablePackage:
    name: str
    version: str
    vulns: list[Vulnerability] = field(default_factory=list)

    def highest_fix_version(self) -> str | None:
        """Return the highest fix version across all vulnerabilities, or None."""
        all_fixes = [v for vuln in self.vulns for v in vuln.fix_versions]
        if not all_fixes:
            return None
        return str(max(all_fixes, key=Version))


@dataclass
class UpgradeResult:
    package: VulnerablePackage
    new_version: str | None
