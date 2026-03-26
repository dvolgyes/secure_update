# secure-update

[![CI](https://github.com/dvolgyes/secure_update/actions/workflows/ci.yml/badge.svg)](https://github.com/dvolgyes/secure_update/actions/workflows/ci.yml)

Automated security upgrade tool for `uv`-managed Python projects.

`secure-update` scans directories for `uv.lock` files, audits them for known
vulnerabilities using `uv-secure`, and upgrades only the affected packages —
without touching the rest of the lockfile and without resolving to package
versions that are too new to be trusted.

## What it does

For each `uv.lock` found:

1. Runs `uvx uv-secure --format json` to identify vulnerable packages
1. Selects the **highest fix version** across all CVEs reported for each package
   (e.g. if urllib3 has three CVEs with fix versions 2.6.0, 2.6.0, and 2.6.3,
   it upgrades to ≥2.6.3)
1. Runs `uv lock --upgrade-package "pkg>=fix_ver" --exclude-newer DATE` —
   targeting only the vulnerable packages, leaving everything else pinned
1. Prints a per-vulnerability report to stdout:

```
urllib3 | 2.4.0 | GHSA-38jv-5279-wg99 | 2.6.3
diskcache | 5.6.3 | GHSA-w8v5-vhqr-4h9v | remains vulnerable
```

## The install-time infection risk

When `uv add pkg` or `pip install pkg` resolves a package, Python packages can
execute arbitrary code at install time via `setup.py`, build hooks in
`pyproject.toml`, or C extension compilation. This is a real supply-chain
attack vector:

- An attacker compromises a maintainer account and publishes a malicious version
- A typosquatting package appears on PyPI moments before your CI runs
- A legitimate package receives a backdoored update

A package published **today** has had zero community scrutiny. The `--exclude-newer`
flag in `uv` limits candidate packages to those uploaded before a given date,
enforcing a trust window. If you set it to 7 days ago, only packages with at
least a week of public exposure are eligible — long enough for the security
community to notice and report obvious malicious releases before they reach your
environment.

`uv` already reduces this risk by preferring pre-built wheels over source
distributions (no `setup.py` execution in the common case). `--exclude-newer`
adds a time-based layer on top.

## uv-secure

`uv-secure` checks a `uv.lock`, `pylock.toml`, or `requirements.txt` against
the [OSV vulnerability database](https://osv.dev) and reports known CVEs.

**Standalone:**

```bash
uvx uv-secure uv.lock                    # table output
uvx uv-secure --format json uv.lock      # JSON for scripting
uvx uv-secure --severity high uv.lock    # filter by severity
```

**Pre-commit integration** — add to `.pre-commit-config.yaml` to block commits
that introduce or retain known vulnerabilities in `uv.lock`:

```yaml
- repo: local
  hooks:
    - id: uv-secure
      name: uv-secure
      entry: uvx uv-secure
      language: system
      files: uv\.lock$
      pass_filenames: true
```

## Safe targeted upgrade with uv

### The problem with naive upgrades

```bash
uv lock --upgrade                  # upgrades everything — risky, changes too much
uv lock --upgrade-package urllib3  # upgrades to the absolute latest — may be brand-new
```

### The safe pattern

Combine `--upgrade-package` with a version floor and `--exclude-newer`.
Use shell command substitution to compute the cutoff date dynamically — no
hardcoded dates in scripts:

```bash
# Upgrade only urllib3, to at least 2.6.3, but not to anything published
# in the last 7 days
uv lock \
  --upgrade-package "urllib3>=2.6.3" \
  --exclude-newer $(date --utc -d "7 days ago" "+%Y-%m-%dT%H:%M:%SZ")

# Multiple vulnerable packages at once
uv lock \
  --upgrade-package "urllib3>=2.6.3" \
  --upgrade-package "aiohttp>=3.10.11" \
  --exclude-newer $(date --utc -d "7 days ago" "+%Y-%m-%dT%H:%M:%SZ")

# Other relative expressions accepted by GNU date
--exclude-newer $(date --utc -d "2 weeks ago"  "+%Y-%m-%dT%H:%M:%SZ")
--exclude-newer $(date --utc -d "1 month ago"  "+%Y-%m-%dT%H:%M:%SZ")
--exclude-newer $(date --utc -d "3 months ago" "+%Y-%m-%dT%H:%M:%SZ")
```

On macOS (BSD date), the syntax differs:

```bash
--exclude-newer $(date -u -v-7d "+%Y-%m-%dT%H:%M:%SZ")   # 7 days ago
--exclude-newer $(date -u -v-2w "+%Y-%m-%dT%H:%M:%SZ")   # 2 weeks ago
--exclude-newer $(date -u -v-1m "+%Y-%m-%dT%H:%M:%SZ")   # 1 month ago
```

`--upgrade-package` upgrades only the named package (and its transitive
dependencies if forced by the new version constraint). All other locked versions
remain unchanged.

`--exclude-newer` accepts an ISO 8601 date (`YYYY-MM-DD`) or RFC 3339 timestamp.
`uv` also supports `--exclude-newer-package pkg=DATE` for per-package cutoffs.

### uv add with --exclude-newer

When adding a new dependency, the same flag applies:

```bash
uv add "requests>=2.32.3" \
  --exclude-newer $(date --utc -d "7 days ago" "+%Y-%m-%dT%H:%M:%SZ")
```

This ensures the newly resolved version of `requests` (and all its dependencies)
was published before the cutoff date.

## secure-update CLI

### Installation

```bash
# Run directly from GitHub
uvx --from git+https://github.com/dvolgyes/secure_update secure-update

# Pin to a specific branch, tag, or commit
uvx --from "git+https://github.com/dvolgyes/secure_update@main" secure-update
uvx --from "git+https://github.com/dvolgyes/secure_update@v1.2.0" secure-update
uvx --from "git+https://github.com/dvolgyes/secure_update@a1b2c3d" secure-update

# Install persistently as a uv tool
uv tool install git+https://github.com/dvolgyes/secure_update
```

### Usage

```bash
# Dry run — show what would be upgraded, make no changes
secure-update --dry-run /path/to/project

# Upgrade vulnerable packages (default: exclude packages newer than 7 days)
secure-update /path/to/project

# Custom trust window
secure-update --older 14d /path/to/project
secure-update --older "2 weeks" /path/to/project
secure-update --older 72h /path/to/project
secure-update --older "1 month" /path/to/project

# Scan multiple projects at once
secure-update ~/projects/foo ~/projects/bar

# With debug logging and log file
secure-update --loglevel DEBUG --logfile audit.log /path/to/project
```

Accepted `--older` formats: `Nd`, `N days`, `Nh`, `N hours`, `Nw`, `N weeks`,
`Nm`, `N months`, `Ny`, `N years` (case-insensitive).

### Output

The report is written to stdout (pipe-friendly). Log messages go to stderr.

```
package | old_version | CVE-ID | new_version
package | old_version | CVE-ID | remains vulnerable
```

A package reports `remains vulnerable` if no fix version is known, if the fix
version is newer than the `--older` cutoff, or if the resolver could not satisfy
the constraint.

## Development

```bash
uv run pytest -n 8 --cov     # run test suite
pre-commit run --all          # lint, type-check, format
```
