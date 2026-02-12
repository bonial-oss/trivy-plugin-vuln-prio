// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// TableConfig controls which columns are displayed and how rows are sorted.
type TableConfig struct {
	ShowEPSS bool
	ShowKEV  bool
	ShowRisk bool   // true only when both EPSS and KEV enabled
	SortBy   string // "risk", "epss", "severity", "cve", "" (preserve order)
}

// vulnRow holds a reference to a vulnerability for table rendering.
type vulnRow struct {
	vuln  *types.Vulnerability
	index int // original index for stable sort
}

// WriteTable writes an enriched report as a formatted table.
func WriteTable(w io.Writer, report *types.Report, cfg TableConfig) error {
	// Step 1: Collect all vulnerabilities across all results into a flat slice.
	var rows []vulnRow
	idx := 0
	for i := range report.Results {
		for j := range report.Results[i].Vulnerabilities {
			rows = append(rows, vulnRow{
				vuln:  &report.Results[i].Vulnerabilities[j],
				index: idx,
			})
			idx++
		}
	}

	// Step 2: Sort by the configured field.
	sortRows(rows, cfg.SortBy)

	// Step 3: Write header and data rows.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	header := buildHeader(cfg)
	fmt.Fprintln(tw, header)

	for _, row := range rows {
		line := buildRow(row.vuln, cfg)
		fmt.Fprintln(tw, line)
	}

	return tw.Flush()
}

// severityRank returns a numeric rank for sorting (higher = more severe).
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "NEGLIGIBLE":
		return 1
	default:
		return 0 // UNKNOWN or unrecognized
	}
}

// sortRows sorts the vulnerability rows based on the given sort key.
func sortRows(rows []vulnRow, sortBy string) {
	switch sortBy {
	case "risk":
		sort.SliceStable(rows, func(i, j int) bool {
			ri := riskValue(rows[i].vuln)
			rj := riskValue(rows[j].vuln)
			return ri > rj // descending
		})
	case "epss":
		sort.SliceStable(rows, func(i, j int) bool {
			ei := epssValue(rows[i].vuln)
			ej := epssValue(rows[j].vuln)
			return ei > ej // descending
		})
	case "severity":
		sort.SliceStable(rows, func(i, j int) bool {
			si := severityRank(rows[i].vuln.Severity)
			sj := severityRank(rows[j].vuln.Severity)
			return si > sj // descending
		})
	case "cve":
		sort.SliceStable(rows, func(i, j int) bool {
			return rows[i].vuln.VulnerabilityID < rows[j].vuln.VulnerabilityID // ascending
		})
	default:
		// Empty string or unrecognized: preserve original order.
	}
}

// riskValue extracts the risk score from a vulnerability, returning 0 if nil.
func riskValue(v *types.Vulnerability) float64 {
	if v.VulnPrio != nil && v.VulnPrio.Risk != nil {
		return *v.VulnPrio.Risk
	}
	return 0
}

// epssValue extracts the EPSS score from a vulnerability, returning 0 if nil.
func epssValue(v *types.Vulnerability) float64 {
	if v.VulnPrio != nil && v.VulnPrio.EPSS != nil && v.VulnPrio.EPSS.Score != nil {
		return *v.VulnPrio.EPSS.Score
	}
	return 0
}

// buildHeader constructs the header row based on enabled columns.
func buildHeader(cfg TableConfig) string {
	cols := []string{"CVE", "Severity", "Package", "Installed"}
	if cfg.ShowRisk {
		cols = append(cols, "Risk")
	}
	if cfg.ShowEPSS {
		cols = append(cols, "EPSS", "EPSS %ile")
	}
	if cfg.ShowKEV {
		cols = append(cols, "KEV")
	}
	return strings.Join(cols, "\t")
}

// buildRow constructs a data row for a single vulnerability.
func buildRow(v *types.Vulnerability, cfg TableConfig) string {
	cols := []string{
		v.VulnerabilityID,
		v.Severity,
		v.PkgName,
		v.InstalledVersion,
	}

	if cfg.ShowRisk {
		cols = append(cols, formatRisk(v))
	}
	if cfg.ShowEPSS {
		cols = append(cols, formatEPSSScore(v), formatEPSSPercentile(v))
	}
	if cfg.ShowKEV {
		cols = append(cols, formatKEV(v))
	}

	return strings.Join(cols, "\t")
}

// formatRisk formats the risk score or returns "-" if nil.
func formatRisk(v *types.Vulnerability) string {
	if v.VulnPrio != nil && v.VulnPrio.Risk != nil {
		return fmt.Sprintf("%.1f", *v.VulnPrio.Risk)
	}
	return "-"
}

// formatEPSSScore formats the EPSS score or returns "-" if nil.
func formatEPSSScore(v *types.Vulnerability) string {
	if v.VulnPrio != nil && v.VulnPrio.EPSS != nil && v.VulnPrio.EPSS.Score != nil {
		return fmt.Sprintf("%.2f", *v.VulnPrio.EPSS.Score)
	}
	return "-"
}

// formatEPSSPercentile formats the EPSS percentile (0-1 scaled to 0-100) or returns "-" if nil.
func formatEPSSPercentile(v *types.Vulnerability) string {
	if v.VulnPrio != nil && v.VulnPrio.EPSS != nil && v.VulnPrio.EPSS.Percentile != nil {
		return fmt.Sprintf("%.1f", *v.VulnPrio.EPSS.Percentile*100)
	}
	return "-"
}

// formatKEV returns "YES" if the vulnerability is in the KEV catalog, "NO" otherwise.
func formatKEV(v *types.Vulnerability) string {
	if v.VulnPrio != nil && v.VulnPrio.KEV != nil && v.VulnPrio.KEV.Listed {
		return "YES"
	}
	return "NO"
}
