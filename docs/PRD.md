# trivy-plugin-vuln-prio — Product Requirements Document

## Problem Statement

Trivy identifies vulnerabilities but provides no built-in mechanism for prioritization.
Security teams face hundreds or thousands of findings per scan with no way to distinguish besides severity
which vulnerabilities pose the greatest real-world risk.
Without exploit likelihood data, organizations treat all findings equally - leading to alert fatigue,
misallocated remediation effort, and unaddressed high-risk issues.

## Product Overview

`trivy-plugin-vuln-prio` is a Trivy output plugin that enriches vulnerability scan results with
exploit prediction data, known exploitation status, and a composite risk score.
It enables teams to prioritize remediation by answering:
*"Which of these vulnerabilities are most likely to be exploited?"*

**Repository:** `github.com/bonial-oss/trivy-plugin-vuln-prio`
**Language:** Go (as used by Trivy)
**License:** Apache-2.0 (REUSE compliant)
**Copyright:** 2026 Bonial International GmbH

## Target Users

- **Security engineers** triaging vulnerability scan results
- **Platform teams** integrating Trivy into CI pipelines
- **Developers** reviewing vulnerability reports for their dependencies

## Data Sources

### EPSS (Exploit Prediction Scoring System)

| Property            | Value                                                                                                                                                 |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Provider            | FIRST (Forum of Incident Response and Security Teams)                                                                                                 |
| Source              | `https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz`                                                                                    |
| Stale data fallback | If today's file is unavailable, falls back to the previous day's file. If both downloads fail, uses locally cached data when available (see NFR-1.4). |
| Update frequency    | Daily                                                                                                                                                 |
| Data per CVE        | Score (0–1 probability of exploitation within 30 days), percentile (0–1)                                                                              |
| Dataset size        | ~315,000 CVEs                                                                                                                                         |

- [Website](https://www.first.org/epss/)

### CISA KEV (Known Exploited Vulnerabilities)

| Property         | Value                                                                                                          |
|------------------|----------------------------------------------------------------------------------------------------------------|
| Provider         | CISA (US Government)                                                                                           |
| Source           | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`                          |
| Fallback         | `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` (GitHub mirror) |
| Update frequency | Weekdays during US Eastern business hours                                                                      |
| Data per CVE     | dateAdded, dueDate, knownRansomwareCampaignUse, vendorProject, product                                         |
| Dataset size     | ~1,250 CVEs                                                                                                    |

- [Website](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Composite Risk Score

A composite risk score (0.0–100.0) computed using the formula
from [Grype](https://github.com/anchore/grype) (Apache-2.0, Anchore, Inc.):

```text
risk = min(threat × severity × kevModifier, 1.0) × 100
```

- **threat:** `1.0` if in KEV, else EPSS score (0–1), else `0.0`
- **severity:**
  average of (string severity mapped to 0–1, CVSS base score / 10);
  falls back to string severity alone when no CVSS score is available
- **kevModifier:** `1.1` if ransomware campaign known, `1.05` if in KEV, else `1.0`

Severity-to-score mapping:

| Severity               | Score |
|------------------------|-------|
| CRITICAL               | 9.0   |
| HIGH                   | 7.5   |
| MEDIUM                 | 5.0   |
| LOW                    | 3.0   |
| NEGLIGIBLE             | 0.5   |
| UNKNOWN / unrecognized | 5.0   |

Scores are divided by 10 before use in the formula (e.g., CRITICAL → 0.9).

## Requirements

### Functional Requirements

#### FR-1: Enrichment

| ID     | Requirement                                                                                                                                                            | Priority |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| FR-1.1 | Enrich each vulnerability with EPSS score and percentile                                                                                                               | Must     |
| FR-1.2 | Enrich each vulnerability with CISA KEV status and metadata                                                                                                            | Must     |
| FR-1.3 | Compute composite risk score for each vulnerability when both EPSS and KEV enrichment are enabled (fallback values used when a specific CVE has no data in one source) | Must     |
| FR-1.4 | Enrich suppressed/ignored vulnerabilities  with the same data                                                                                                          | Must     |
| FR-1.5 | Allow disabling EPSS enrichment via `--no-epss`                                                                                                                        | Must     |
| FR-1.6 | Allow disabling KEV enrichment via `--no-kev`                                                                                                                          | Must     |
| FR-1.7 | When both `--no-epss` and `--no-kev` are specified, still pass through all Trivy data with an empty `VulnPrio` object; table output hides all enrichment columns       | Must     |

#### FR-2: Input

| ID     | Requirement                                                           | Priority |
|--------|-----------------------------------------------------------------------|----------|
| FR-2.1 | Accept Trivy JSON format from stdin                                   | Must     |
| FR-2.2 | Accept SARIF format from stdin                                        | Must     |
| FR-2.3 | Auto-detect input format (Trivy JSON vs SARIF)                        | Must     |
| FR-2.4 | Reject incompatible input/output format combinations with exit code 3 | Must     |

#### FR-3: Output

| ID     | Requirement                                                                                                                                              | Priority |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------|----------|
| FR-3.1 | Output enriched Trivy JSON preserving all original fields                                                                                                | Must     |
| FR-3.2 | Output enriched SARIF with VulnPrio data in the properties bag                                                                                           | Must     |
| FR-3.3 | Output human-readable table with configurable columns                                                                                                    | Must     |
| FR-3.4 | Table output matches Trivy's native table format (borders, auto-merge, row separators, ANSI styling)                                                     | Must     |
| FR-3.5 | Table supports sorting by: risk (default), EPSS, severity, CVE ID                                                                                        | Must     |
| FR-3.6 | Table displays suppressed vulnerabilities in a separate section (shown by default)                                                                       | Must     |
| FR-3.7 | Allow hiding suppressed vulnerabilities via `--hide-suppressed` (table: hides section; JSON: removes `ExperimentalModifiedFindings`; no effect on SARIF) | Must     |
| FR-3.8 | Write output to file instead of stdout via `--output` / `-o`                                                                                             | Should   |

#### FR-4: Filtering

| ID     | Requirement                                                                                                       | Priority |
|--------|-------------------------------------------------------------------------------------------------------------------|----------|
| FR-4.1 | Filter vulnerabilities below an EPSS score threshold (`--epss-threshold`). Applies to JSON and table output only. | Must     |
| FR-4.2 | Filter to only KEV-listed vulnerabilities (`--kev-only`). Applies to JSON and table output only.                  | Must     |
| FR-4.3 | Suppressed vulnerabilities are never removed by `--epss-threshold` or `--kev-only` filtering                      | Must     |
| FR-4.4 | Filtering flags have no effect on SARIF output (SARIF always includes all results)                                | Must     |

#### FR-5: CI Policy Enforcement

| ID     | Requirement                                                                               | Priority |
|--------|-------------------------------------------------------------------------------------------|----------|
| FR-5.1 | Exit code 1 when any KEV vulnerability is found (`--fail-on-kev`)                         | Must     |
| FR-5.2 | Exit code 1 when any vulnerability exceeds an EPSS threshold (`--fail-on-epss-threshold`) | Must     |
| FR-5.3 | Suppressed vulnerabilities do not trigger policy violations                               | Must     |

### Non-Functional Requirements

#### NFR-1: Caching

| ID      | Requirement                                                                                                                                  | Priority |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------|----------|
| NFR-1.1 | Cache EPSS and KEV datasets locally with a 24-hour TTL                                                                                       | Must     |
| NFR-1.2 | Default cache directory: `~/.trivy/plugins/vuln-prio/`; when `$XDG_DATA_HOME` is set, defaults to `$XDG_DATA_HOME/.trivy/plugins/vuln-prio/` | Must     |
| NFR-1.3 | Allow overriding cache directory via `--cache-dir`                                                                                           | Must     |
| NFR-1.4 | Gracefully degrade to stale cache when download fails                                                                                        | Must     |
| NFR-1.5 | Skip freshness check entirely via `--skip-db-update`                                                                                         | Must     |
| NFR-1.6 | Exit code 2 if download fails and no cache exists                                                                                            | Must     |

#### NFR-2: Compatibility

| ID      | Requirement                                                             | Priority |
|---------|-------------------------------------------------------------------------|----------|
| NFR-2.1 | Preserve all Trivy JSON fields not consumed by the plugin (passthrough) | Must     |
| NFR-2.2 | Work as a Trivy output plugin (`plugin.yaml` with `output: true`)       | Must     |
| NFR-2.3 | Work standalone via pipe (`trivy ... \| vuln-prio`)                     | Must     |
| NFR-2.4 | Support darwin/linux on amd64/arm64                                     | Must     |

#### NFR-3: Licensing & Compliance

| ID      | Requirement                                                               | Priority |
|---------|---------------------------------------------------------------------------|----------|
| NFR-3.1 | Apache-2.0 licensed, REUSE compliant                                      | Must     |
| NFR-3.2 | Dual copyright attribution on risk score formula (Anchore, Inc. + Bonial) | Must     |
| NFR-3.3 | REUSE compliance enforced via CI                                          | Must     |

## CLI Interface

### Usage

As output plugin:

```bash
trivy image \
  --format json \
  --output plugin=vuln-prio \
  --output-plugin-arg "--format table" \
  alpine:latest
```

Via pipe:

```bash
trivy image --format json alpine:latest | trivy vuln-prio --format table
trivy fs --format sarif . | trivy vuln-prio --format sarif
```

### Flags

| Flag                       | Type   | Default         | Description                                      |
|----------------------------|--------|-----------------|--------------------------------------------------|
| `--no-epss`                | bool   | `false`         | Disable EPSS enrichment                          |
| `--no-kev`                 | bool   | `false`         | Disable KEV enrichment                           |
| `--format`                 | string | `json`          | Output format: `json`, `table`, `sarif`          |
| `--output`, `-o`           | string | ``              | Write to file instead of stdout                  |
| `--epss-threshold`         | float  | `0.0`           | Only show vulns with EPSS score >= value         |
| `--kev-only`               | bool   | `false`         | Only show vulns present in KEV catalog           |
| `--fail-on-kev`            | bool   | `false`         | Exit code 1 if any KEV vuln is found             |
| `--fail-on-epss-threshold` | float  | `0.0`           | Exit code 1 if any vuln has EPSS >= value        |
| `--sort-by`                | string | `risk`          | Sort table by: `risk`, `epss`, `severity`, `cve` |
| `--skip-db-update`         | bool   | `false`         | Use cached data, don't check for updates         |
| `--cache-dir`              | string | *(see NFR-1.2)* | Override cache location                          |
| `--hide-suppressed`        | bool   | `false`         | Exclude suppressed/ignored vulnerabilities       |

### Exit Codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Success, no policy violations                                    |
| 1    | Policy violation (`--fail-on-kev` or `--fail-on-epss-threshold`) |
| 2    | Runtime error (no input, network failure with no cache, etc.)    |
| 3    | Input/output format mismatch                                     |

### Format Compatibility Matrix

| Input      | `--format json` | `--format table` | `--format sarif` |
|------------|-----------------|------------------|------------------|
| Trivy JSON | OK              | OK               | Exit 3           |
| SARIF      | Exit 3          | Exit 3           | OK               |

## Output Specifications

### JSON

Each vulnerability gains a `VulnPrio` object:

```json
{
  "VulnerabilityID": "CVE-2024-1234",
  "PkgName": "openssl",
  "Severity": "CRITICAL",
  "VulnPrio": {
    "risk": 97.0,
    "epss": {
      "score": 0.97,
      "percentile": 0.998,
      "modelVersion": "v2025.03.14",
      "scoreDate": "2026-02-12T00:00:00+0000"
    },
    "kev": {
      "listed": true,
      "dateAdded": "2021-11-03",
      "dueDate": "2021-11-17",
      "knownRansomwareCampaignUse": "Known",
      "vendorProject": "Accellion",
      "product": "FTA"
    }
  }
}
```

**Null/absent handling:**

- CVE not in EPSS: `epss.score: null`, `epss.percentile: null`
- CVE not in KEV: `kev.listed: false`, other KEV fields omitted
- `--no-epss`: `epss` key omitted entirely
- `--no-kev`: `kev` key omitted entirely
- `--no-epss` or `--no-kev` used: `risk` key omitted (requires both data sources)

### SARIF

Enrichment in the `properties` bag on each SARIF `result`:

```json
{
  "ruleId": "CVE-2024-1234",
  "properties": {
    "vulnPrio": { "risk": 97.0, "epss": {...}, "kev": {...} }
  }
}
```

SARIF-specific behavior:

- Severity and CVSS data are extracted from the matching rule definition (`tool.driver.rules[]`) for each result (linked via `ruleId`/`ruleIndex`):
  - **Severity string:** Trivy includes the severity string (e.g. `"CRITICAL"`, `"HIGH"`) in `rules[].properties.tags` (currently as the last element, but the implementation should defensively scan the array for a recognized severity value). This preserves all five Trivy severity levels.
  - **CVSS base score:** `rules[].properties.cvssv3_baseScore` (float64) and/or `rules[].properties.cvssv40_baseScore` (float64), present when non-zero. Used as the CVSS component of the risk formula, averaged with the string-severity score (matching Trivy JSON behavior).
  - Trivy also emits `rules[].properties.security-severity` (string-encoded float, either the CVSS V3 score or a fallback from the severity name), but this field is not used — the explicit CVSS base score fields above are preferred.
- Fallback: if a result cannot be matched to a rule or the rule lacks severity/CVSS properties, the SARIF `level` field is mapped as a last resort: `error` → HIGH, `warning` → MEDIUM, `note` → LOW, other → MEDIUM. This fallback loses granularity (Trivy maps both CRITICAL and HIGH to `error`, and both LOW and UNKNOWN to `note`).

## Release Strategy

- **Build tool:** GoReleaser
- **Platforms:** darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
- **Archives:** `vuln-prio_<version>_<os>-<arch>.tar.gz`
- **Trigger:** Git tag push (`v*`) via GitHub Actions
- **Distribution:** GitHub Releases
