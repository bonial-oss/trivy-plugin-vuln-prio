# CLI Interface

## Usage

As output plugin:

```bash
trivy image \
  --format json \
  --output plugin=vuln-prio \
  alpine:latest
```

As output plugin with table output:

```bash
trivy image \
  --format json \
  --output plugin=vuln-prio \
  --output-plugin-arg "--format table" \
  alpine:latest
```

Via pipe:

```bash
trivy image --format json alpine:latest | trivy vuln-prio
trivy image --format json alpine:latest | trivy vuln-prio --format table
trivy fs --format sarif . | trivy vuln-prio
```

## Flags

| Flag                       | Type   | Default                       | Description                                       |
|----------------------------|--------|-------------------------------|---------------------------------------------------|
| `--format`                 | string |                               | Output format override; only valid value: `table` |
| `--output`, `-o`           | string |                               | Write to file instead of stdout                   |
| `--no-epss`                | bool   | `false`                       | Disable EPSS enrichment                           |
| `--no-kev`                 | bool   | `false`                       | Disable KEV enrichment                            |
| `--epss-threshold`         | float  | `0.0`                         | Only show vulns with EPSS score >= value          |
| `--kev-only`               | bool   | `false`                       | Only show vulns present in KEV catalog            |
| `--fail-on-kev`            | bool   | `false`                       | Exit code 1 if any KEV vuln is found              |
| `--fail-on-epss-threshold` | float  | `0.0`                         | Exit code 1 if any vuln has EPSS >= value         |
| `--sort-by`                | string | `risk`                        | Sort table by: `risk`, `epss`, `severity`, `cve`  |
| `--skip-db-update`         | bool   | `false`                       | Use cached data, don't check for updates          |
| `--cache-dir`              | string | `~/.trivy/plugins/vuln-prio/` | Override cache location                           |
| `--hide-suppressed`        | bool   | `false`                       | Exclude suppressed/ignored vulnerabilities        |

By default (no `--format` flag), the output format matches the detected input format:
Trivy JSON input produces enriched JSON output, SARIF input produces enriched SARIF output.

The `--format table` flag switches output to a human-readable table and requires Trivy JSON input.

## Exit Codes

| Code | Meaning                                                          |
|------|------------------------------------------------------------------|
| 0    | Success, no policy violations                                    |
| 1    | Policy violation (`--fail-on-kev` or `--fail-on-epss-threshold`) |
| 2    | Runtime error (no input, network failure with no cache, etc.)    |
| 3    | Input/output format mismatch                                     |
