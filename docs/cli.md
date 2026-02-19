# CLI Interface

## Usage

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

## Flags

| Flag                       | Type   | Default                       | Description                                      |
|----------------------------|--------|-------------------------------|--------------------------------------------------|
| `--format`                 | string | `json`                        | Output format: `json`, `table`, `sarif`          |
| `--output`, `-o`           | string |                               | Write to file instead of stdout                  |
| `--no-epss`                | bool   | `false`                       | Disable EPSS enrichment                          |
| `--no-kev`                 | bool   | `false`                       | Disable KEV enrichment                           |
| `--epss-threshold`         | float  | `0.0`                         | Only show vulns with EPSS score >= value         |
| `--kev-only`               | bool   | `false`                       | Only show vulns present in KEV catalog           |
| `--fail-on-kev`            | bool   | `false`                       | Exit code 1 if any KEV vuln is found             |
| `--fail-on-epss-threshold` | float  | `0.0`                         | Exit code 1 if any vuln has EPSS >= value        |
| `--sort-by`                | string | `risk`                        | Sort table by: `risk`, `epss`, `severity`, `cve` |
| `--skip-db-update`         | bool   | `false`                       | Use cached data, don't check for updates         |
| `--cache-dir`              | string | `~/.trivy/plugins/vuln-prio/` | Override cache location                          |
| `--hide-suppressed`        | bool   | `false`                       | Exclude suppressed/ignored vulnerabilities       |

## Exit Codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Success, no policy violations                                    |
| 1    | Policy violation (`--fail-on-kev` or `--fail-on-epss-threshold`) |
| 2    | Runtime error (no input, network failure with no cache, etc.)    |
| 3    | Input/output format mismatch                                     |

## Format Compatibility Matrix

| Input      | `--format json` | `--format table` | `--format sarif` |
|------------|-----------------|------------------|------------------|
| Trivy JSON | OK              | OK               | Exit 3           |
| SARIF      | Exit 3          | Exit 3           | OK               |
