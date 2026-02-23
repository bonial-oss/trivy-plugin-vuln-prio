# trivy-plugin-vuln-prio

A Trivy output plugin that enriches vulnerability scan results with EPSS
exploit prediction scores, CISA Known Exploited Vulnerabilities (KEV) catalog
data, and a composite risk score. Supports JSON, table, and SARIF output
formats with filtering, sorting, and CI exit code policies.

## Usage

Please find details at the [CLI documentation](cli.md).

## Data Sources

| Source     | Provider      | Description                                                                    |
|------------|---------------|--------------------------------------------------------------------------------|
| EPSS       | FIRST         | Exploit Prediction Scoring System — probability of exploitation within 30 days |
| CISA KEV   | CISA          | Known Exploited Vulnerabilities catalog                                        |
| Risk Score | Grype formula | Composite score (0–100) combining threat, severity, and KEV status             |
