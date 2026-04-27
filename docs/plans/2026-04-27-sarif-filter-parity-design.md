<!-- SPDX-FileCopyrightText: 2026 Bonial International GmbH -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# SARIF Filter Parity — Design

**Status:** Draft

**Goal:** Bring SARIF enrichment to feature parity with the JSON path for the
filtering and suppression flags that are silently ignored today.

**Context:** During end-to-end testing against
`bonial-internal/backstage-maintainers/backstage` (147 SARIF findings, 0 KEV
hits, top risk 1.48), the SARIF code path applied EPSS / KEV / risk
enrichment correctly and propagated `--fail-on-kev` /
`--fail-on-epss-threshold` policy violations through the Trivy output-plugin
protocol (verified both `trivy ... | trivy vuln-prio` and
`trivy ... --output plugin=vuln-prio --output-plugin-arg "..."`; outputs were
byte-identical). Three CLI flags were observed to be **silently ignored** on
SARIF input: `--epss-threshold`, `--kev-only`, `--hide-suppressed`.

---

## Issues Found

### Issue 1 — `--epss-threshold N` ignored for SARIF

**Severity:** Functional gap.

**Symptom:** Running `trivy fs -f sarif … | trivy vuln-prio --epss-threshold 0.01`
on the backstage scan kept all 147 results, although only 1 had
`epss.score >= 0.01`.

**Root cause:** `internal/enricher/sarif.go:22-75` (`EnrichSARIF`) reads the
config's `FailOnKEV` / `FailOnEPSSThreshold` for policy checks, but does not
read or apply `EPSSThreshold` / `KEVOnly`. Compare to
`internal/enricher/enricher.go:63-80`, where the JSON path rebuilds
`res.Vulnerabilities` as a filtered slice when either flag is set.

**Documented behaviour:** `docs/cli.md:40-41` lists `--epss-threshold` and
`--kev-only` as filter flags with no input-format caveat — the help text
implies SARIF support.

### Issue 2 — `--kev-only` ignored for SARIF

Same root cause as Issue 1; the SARIF enrichment never consults `cfg.KEVOnly`.
Mentioned separately because the user-visible behaviour (no filtering vs.
"only KEV") differs and tests should cover it independently.

### Issue 3 — `--hide-suppressed` ignored for SARIF

**Symptom:** `cmd/root.go:195-199` only zeroes
`ExperimentalModifiedFindings` for the JSON output path. The SARIF branch
(`cmd/root.go:217-227`) writes the report unchanged.

**Root cause:** SARIF doesn't have a separate "modified findings" list. Per
SARIF v2.1.0 spec §3.27.23, suppressed findings stay in the same
`runs[].results[]` array and carry a `result.suppressions` field (an array of
Suppression objects). The plugin already preserves arbitrary unknown SARIF
fields via `SARIFResult.Extras` (`internal/types/sarif.go:93,141-149`), so the
data is reachable without a typed model change. The flag handler was never
written.

**Open question:** Trivy's SARIF emitter — when does it actually populate
`result.suppressions`? Confirmed needed before implementation:

```bash
# in a project that has a .trivyignore matching some CVE
trivy fs -f sarif --output /tmp/with-suppressions.sarif .
jq '[.runs[].results[] | select(.suppressions)] | length' /tmp/with-suppressions.sarif
```

If Trivy emits empty `suppressions: []` for unsuppressed results, the filter
must also check the array length (not just key presence).

---

## Proposed Approach

Add a single filtering pass at the end of `EnrichSARIF`, mirroring the
JSON path's shape but adapted to SARIF semantics. The pass runs **after** the
existing per-result enrichment loop so policy checks continue to evaluate
every finding (KEV / threshold breaches in suppressed results still fail the
build, matching SARIF's "consult, don't hide" intent of the suppressions
field).

Sketch (illustrative, not final):

```go
// After the enrichment loop, before computing PolicyViolation.
if cfg.EPSSThreshold > 0 || cfg.KEVOnly || cfg.HideSuppressed {
    filtered := make([]types.SARIFResult, 0, len(run.Results))
    for _, r := range run.Results {
        if cfg.HideSuppressed && hasActiveSuppression(r) {
            continue
        }
        if cfg.EPSSThreshold > 0 && !meetsEPSSThreshold(r, cfg.EPSSThreshold) {
            continue
        }
        if cfg.KEVOnly && !isKEVListed(r) {
            continue
        }
        filtered = append(filtered, r)
    }
    run.Results = filtered
}
```

`hasActiveSuppression`, `meetsEPSSThreshold`, and `isKEVListed` are small
helpers reading from `r.Extras["suppressions"]` and `r.Properties["vulnPrio"]`
respectively.

### Design Decision Needed — Policy interaction with filtering

In the JSON path (`enricher.go:83-98`), policy checks run **after** filtering,
so a finding filtered out by `--epss-threshold 0.5` cannot fail a
`--fail-on-epss-threshold 0.3` check. That's a side-effect of operating on the
already-mutated slice.

For SARIF we have a choice — flag this trade-off explicitly so we don't
inherit the JSON quirk by accident:

| Option | Behaviour | Pros | Cons |
|---|---|---|---|
| **A — Match JSON** | Filter first, then policy. Filtered-out findings can't trigger policy. | Symmetric across formats; easy to explain. | Surprising — `--epss-threshold` silently weakens `--fail-on-epss-threshold`. |
| **B — Policy first, then filter** | Compute `PolicyViolation` over all enriched results, then filter for output. | Filtering only affects the report, never the exit code. | Diverges from JSON path; users must learn two rules. |
| **C — Match JSON now, fix both later** | Implement A; track JSON fix in a follow-up issue. | Minimal divergence today. | Defers the surprising behaviour rather than removing it. |

**Recommendation:** Option B for SARIF, plus a follow-up issue to align JSON.
Filtering is a presentation concern; policy is a correctness concern; mixing
them is what produces the surprise.

> **Decision required from maintainer before implementation.**

---

## Out of Scope

- **Severity-based filtering** (`--severity` style) — Trivy itself filters by
  severity before producing SARIF, so adding a plugin-side filter would
  duplicate that. Punt unless someone reports a need.
- **`--format table` for SARIF** — already explicitly rejected with exit code
  3 (`cmd/root.go:117-122`); intentional.
- **Restructuring the JSON filter path** — Option C above keeps JSON
  untouched. Any change there belongs in its own design doc.

---

## Verification Plan

Reuse the existing test pattern in `internal/enricher/sarif_test.go`
(`makeSARIFReportWithTool` helper, fixture EPSS/KEV sources from
`enricher_test.go`).

New test cases to add:

1. `TestEnrichSARIF_EPSSThresholdFilters` — two results, one above and one
   below threshold; assert `len(Results) == 1` after enrichment.
2. `TestEnrichSARIF_KEVOnlyFilters` — two results, one KEV-listed; assert
   filtered to the KEV one.
3. `TestEnrichSARIF_HideSuppressedFilters` — two results, one with
   `suppressions: [{kind: "external"}]` in `Extras`; assert filtered out.
4. `TestEnrichSARIF_PolicyChecksAllResults` (Option B only) — finding above
   `FailOnEPSSThreshold` is also above `EPSSThreshold`; assert
   `PolicyViolation == true` even when filter would have removed it.
5. `TestEnrichSARIF_FilterCombination` — all three filters active
   simultaneously; assert AND semantics (a result must pass every active
   filter).

End-to-end smoke after implementation:

```bash
# Should match the count from the unfiltered run, minus low-EPSS findings.
/path/to/vuln-prio --epss-threshold 0.01 < /tmp/backstage.sarif | \
  jq '.runs[0].results | length'  # expect 1, was 147
```

---

## Files Likely to Change

| Path | Reason |
|---|---|
| `internal/enricher/sarif.go` | Add filtering pass + helpers |
| `internal/enricher/sarif_test.go` | New table tests for the filters |
| `cmd/root.go:195-199` | Drop the JSON-only guard around `HideSuppressed` (it's now handled inside `EnrichSARIF` for SARIF and stays explicit for JSON) |
| `docs/cli.md` | Note any per-format caveats that survive (none expected after this change) |

No type/model changes anticipated — `SARIFResult.Extras` already carries
`suppressions` through.

---

## References

- Test session findings: see commit-less working tree on `main`,
  /tmp/vuln-prio-test/* artefacts (regenerate with the commands in the
  Verification Plan above).
- JSON filter implementation: `internal/enricher/enricher.go:63-80`.
- SARIF enrichment loop: `internal/enricher/sarif.go:22-75`.
- CLI wiring: `cmd/root.go:160-227`.
- SARIF v2.1.0 spec §3.27.23 (suppressions): https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/sarif-v2.1.0-cs01.html#_Toc16012600
