# Changelog

## 0.1.0 (2026-02-26)


### Miscellaneous Chores

* add .gitignore ([29ab241](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/29ab2413301e3bea2edf33abe7b227e89e1ebfef))
* add alternative binary name to .gitignore ([8943212](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/89432127494169f6ceff49076ea12c1249873159))
* add Backstage catalog entry, CODEOWERS file, README.md ([d3c20da](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/d3c20dad42f652ca350f9596ccc496dd93b7a204))
* add license, add REUSE linting ([3369be9](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/3369be9aac3524098d600c71fff2d644846c93c8))
* add Makefile, golangci-lint, and MegaLinter configuration ([010eb97](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/010eb972c78abecc4403bad3bbef6f846dc76fb5))
* extend commitlint scopes for implementation packages ([6605323](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/6605323c1986b78f995f2adbca446e407ba58f89))
* scaffold project ([0a49699](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/0a49699969d7769bcbd7388dba30620f74238023))


### Features

* **cache:** add file-based cache with 24-hour TTL ([2bf7b3c](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/2bf7b3ca555757eec018c92a2791ac0629519366))
* **cli:** add --hide-suppressed flag ([36b4451](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/36b445148228daae6c7daf14f2521002692f7eff))
* **cli:** add cobra CLI and wire up full enrichment pipeline ([f625990](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/f625990d5749b40478020180a0c8e8f61b3abc4c))
* **enricher:** add enricher with filtering and policy enforcement ([be3916a](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/be3916a671c007ae7ced1d6f2f2a5ad35551547e))
* **enricher:** add risk score calculation based on Grype formula ([4376ff6](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/4376ff633bb537a80e7496fba067f1be5f04839d))
* **enricher:** extract enrichVuln helper and enrich modified findings ([d25b5eb](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/d25b5eb0aabfb6cbd0eafcc4864033d710c5696a))
* **epss:** add EPSS data source with download, caching, and CSV parsing ([53641bc](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/53641bcd65ffb5862d1a81fbb1f09eb272fb2f92))
* **input:** add input format detection for Trivy JSON and SARIF ([cf5a380](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/cf5a380e4050754eee89f673e035ad242efc88cc))
* **kev:** add CISA KEV data source with download, caching, and fallback mirror ([04281da](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/04281da9949d650b90b065a168200ce84e67e25d))
* **main:** add plugin.yaml for installation as Trivy plugin ([547c55a](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/547c55a7e0a76e737b2a625440668b6d7f3e1c24))
* **main:** add plugin.yaml for installation as Trivy plugin ([1ed117a](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/1ed117a381616cd8f19204bb9321ab28813c74cf))
* **output:** add ANSI terminal styling matching Trivy's table format ([7b546f3](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/7b546f38d815cde05d57f21ed9334917dae6ae7d))
* **output:** add JSON output writer ([4541b54](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/4541b547741e0cbd5f0c5640be70ad3f7bd13ad5))
* **output:** add suppressed vulnerabilities table with title wrapping ([9404309](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/940430941b99f0eef84f9f7b9f7776eea8f4f8e8))
* **output:** add table output with configurable columns and sorting ([eaeee0e](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/eaeee0e00dade513884ea1c9706b3128fcefd0b9))
* **sarif:** add SARIF enrichment and output ([46ee0b9](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/46ee0b923d13e42f358e900582bf794ee4859c66))
* **types:** add domain types for Trivy report, SARIF, and enrichment data ([3c58d8c](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/3c58d8c512e484399e38d9b18889355f6a71e013))
* **types:** add ModifiedFinding type and Result Extras passthrough ([735ffa3](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/735ffa3fb50fbdd67b4c48614bf18ed7e654ba84))


### Bug Fixes

* **main:** use generic type for release-please extra-files ([2068bbe](https://github.com/bonial-oss/trivy-plugin-vuln-prio/commit/2068bbe01fe1c4ef385d75c8a8f42bb1a75fb32f))
