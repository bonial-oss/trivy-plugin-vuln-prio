// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	aqtable "github.com/aquasecurity/table"
	"github.com/aquasecurity/tml"
	"github.com/fatih/color"
	"golang.org/x/term"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const maxTitleWords = 12

// TableConfig controls which columns are displayed and how rows are sorted.
type TableConfig struct {
	ShowEPSS       bool
	ShowKEV        bool
	ShowRisk       bool   // true only when both EPSS and KEV enabled
	SortBy         string // "risk", "epss", "severity", "cve", "" (preserve order)
	HideSuppressed bool   // exclude suppressed vulnerabilities section
	IsTerminal     bool   // true when output goes to a terminal (enables ANSI styling)
}

// IsOutputToTerminal returns true if the writer is stdout connected to a
// character device (TTY). Matching Trivy's behavior, returns false on Windows.
func IsOutputToTerminal(output io.Writer) bool {
	return output == os.Stdout && term.IsTerminal(int(os.Stdout.Fd()))
}

// vulnRow holds a reference to a vulnerability for table rendering.
type vulnRow struct {
	vuln  *types.Vulnerability
	index int // original index for stable sort
}

// WriteTable writes an enriched report as a table grouped by target.
func WriteTable(w io.Writer, report *types.Report, cfg TableConfig) error {
	first := true
	for i := range report.Results {
		result := &report.Results[i]
		vulns := result.Vulnerabilities
		hasSuppressed := !cfg.HideSuppressed && hasVulnFindings(result.ExperimentalModifiedFindings)

		if len(vulns) == 0 && !hasSuppressed {
			continue
		}

		if !first {
			fmt.Fprintln(w)
		}
		first = false

		writeTargetHeader(w, result, cfg.IsTerminal)

		if len(vulns) > 0 {
			rows := make([]vulnRow, len(vulns))
			for j := range vulns {
				rows[j] = vulnRow{vuln: &vulns[j], index: j}
			}
			sortRows(rows, cfg.SortBy)
			writeVulnTable(w, rows, cfg)
		}

		if hasSuppressed {
			writeSuppressedSection(w, result.ExperimentalModifiedFindings, cfg)
		}
	}

	if first {
		writeVulnTable(w, nil, cfg)
	}

	return nil
}

// writeTargetHeader writes the target name with formatting and severity summary.
func writeTargetHeader(w io.Writer, result *types.Result, isTerminal bool) {
	target := result.Target
	if result.Type != "" {
		target = fmt.Sprintf("%s (%s)", result.Target, result.Type)
	}
	if isTerminal {
		_ = tml.Fprintf(w, "<underline><bold>%s</bold></underline>\n", target)
	} else {
		fmt.Fprintln(w, target)
		fmt.Fprintln(w, strings.Repeat("=", utf8.RuneCountInString(target)))
	}
	fmt.Fprintln(w, severitySummary(result.Vulnerabilities))
	fmt.Fprintln(w)
}

// newTableWriter creates a table writer with the standard configuration
// matching Trivy's output format: borders, auto-merge, and row separators.
// When isTerminal is true, header and line styles use ANSI formatting.
func newTableWriter(w io.Writer, isTerminal bool) *aqtable.Table {
	tw := aqtable.New(w)
	if isTerminal {
		tw.SetHeaderStyle(aqtable.StyleBold)
		tw.SetLineStyle(aqtable.StyleDim)
	}
	tw.SetBorders(true)
	tw.SetAutoMerge(true)
	tw.SetRowLines(true)
	return tw
}

// writeVulnTable renders a vulnerability table using aquasecurity/table.
func writeVulnTable(w io.Writer, rows []vulnRow, cfg TableConfig) {
	tw := newTableWriter(w, cfg.IsTerminal)
	tw.SetHeaders(headerNames(cfg)...)
	for _, row := range rows {
		tw.AddRow(rowCells(row.vuln, cfg)...)
	}
	tw.Render()
}

// writeSuppressedSection renders the suppressed vulnerabilities header and table.
func writeSuppressedSection(w io.Writer, findings []types.ModifiedFinding, cfg TableConfig) {
	var total int
	for i := range findings {
		if findings[i].Type == "vulnerability" {
			total++
		}
	}
	if total == 0 {
		return
	}

	title := fmt.Sprintf("Suppressed Vulnerabilities (Total: %d)", total)
	if cfg.IsTerminal {
		_ = tml.Fprintf(w, "\n<underline>%s</underline>\n\n", title)
	} else {
		fmt.Fprintf(w, "\n%s\n", title)
		fmt.Fprintf(w, "%s\n", strings.Repeat("=", utf8.RuneCountInString(title)))
	}

	tw := newTableWriter(w, cfg.IsTerminal)
	tw.SetHeaders(suppressedHeaderNames(cfg)...)
	for i := range findings {
		if findings[i].Type != "vulnerability" {
			continue
		}
		tw.AddRow(suppressedRowCells(&findings[i], cfg)...)
	}
	tw.Render()
}

// headerNames returns column header names based on config.
func headerNames(cfg TableConfig) []string {
	cols := []string{"Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title"}
	if cfg.ShowRisk {
		cols = append(cols, "Risk")
	}
	if cfg.ShowEPSS {
		cols = append(cols, "EPSS", "EPSS %ile")
	}
	if cfg.ShowKEV {
		cols = append(cols, "KEV")
	}
	return cols
}

// rowCells returns the cell values for a single vulnerability row.
func rowCells(v *types.Vulnerability, cfg TableConfig) []string {
	severity := v.Severity
	if cfg.IsTerminal {
		severity = colorizeSeverity(severity)
	}
	cols := []string{
		v.PkgName,
		v.VulnerabilityID,
		severity,
		extraString(v, "Status"),
		v.InstalledVersion,
		v.FixedVersion,
		titleWithURL(v, cfg.IsTerminal),
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

	return cols
}

// severitySummary returns a line like:
// Total: 5 (UNKNOWN: 0, LOW: 2, MEDIUM: 1, HIGH: 1, CRITICAL: 1)
func severitySummary(vulns []types.Vulnerability) string {
	counts := map[string]int{
		"UNKNOWN":  0,
		"LOW":      0,
		"MEDIUM":   0,
		"HIGH":     0,
		"CRITICAL": 0,
	}
	for _, v := range vulns {
		sev := strings.ToUpper(v.Severity)
		if _, ok := counts[sev]; ok {
			counts[sev]++
		} else {
			counts["UNKNOWN"]++
		}
	}
	return fmt.Sprintf("Total: %d (UNKNOWN: %d, LOW: %d, MEDIUM: %d, HIGH: %d, CRITICAL: %d)",
		len(vulns), counts["UNKNOWN"], counts["LOW"], counts["MEDIUM"], counts["HIGH"], counts["CRITICAL"])
}

// severityColors maps severity names to color functions matching Trivy's palette.
var severityColors = map[string]func(a ...any) string{
	"UNKNOWN":  color.New(color.FgCyan).SprintFunc(),
	"LOW":      color.New(color.FgBlue).SprintFunc(),
	"MEDIUM":   color.New(color.FgYellow).SprintFunc(),
	"HIGH":     color.New(color.FgHiRed).SprintFunc(),
	"CRITICAL": color.New(color.FgRed).SprintFunc(),
}

// colorizeSeverity returns the severity string wrapped in ANSI color codes.
func colorizeSeverity(severity string) string {
	if fn, ok := severityColors[strings.ToUpper(severity)]; ok {
		return fn(severity)
	}
	return severity
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
		return 0
	}
}

// sortRows sorts the vulnerability rows based on the given sort key.
func sortRows(rows []vulnRow, sortBy string) {
	switch sortBy {
	case "risk":
		sort.SliceStable(rows, func(i, j int) bool {
			return riskValue(rows[i].vuln) > riskValue(rows[j].vuln)
		})
	case "epss":
		sort.SliceStable(rows, func(i, j int) bool {
			return epssValue(rows[i].vuln) > epssValue(rows[j].vuln)
		})
	case "severity":
		sort.SliceStable(rows, func(i, j int) bool {
			return severityRank(rows[i].vuln.Severity) > severityRank(rows[j].vuln.Severity)
		})
	case "cve":
		sort.SliceStable(rows, func(i, j int) bool {
			return rows[i].vuln.VulnerabilityID < rows[j].vuln.VulnerabilityID
		})
	default:
		// preserve original order
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

// titleWithURL builds the Title cell content: truncates the title to
// maxTitleWords words (matching Trivy) and appends PrimaryURL on a new line.
// When isTerminal is true, the URL is colored blue.
func titleWithURL(v *types.Vulnerability, isTerminal bool) string {
	title := extraString(v, "Title")
	title = truncateWords(title, maxTitleWords)
	url := extraString(v, "PrimaryURL")
	if url != "" {
		if isTerminal {
			url = tml.Sprintf("<blue>%s</blue>", url)
		}
		if title != "" {
			return title + "\n" + url
		}
		return url
	}
	return title
}

// truncateWords limits text to maxWords words, appending "..." if truncated.
func truncateWords(text string, maxWords int) string {
	words := strings.Fields(text)
	if len(words) <= maxWords {
		return text
	}
	return strings.Join(words[:maxWords], " ") + "..."
}

// extraString extracts a string value from the Extras passthrough map.
func extraString(v *types.Vulnerability, key string) string {
	if v.Extras == nil {
		return ""
	}
	raw, ok := v.Extras[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
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

// suppressedHeaderNames returns column header names for the suppressed section.
func suppressedHeaderNames(cfg TableConfig) []string {
	cols := []string{"Library", "Vulnerability", "Severity", "Status", "Statement", "Source"}
	if cfg.ShowRisk {
		cols = append(cols, "Risk")
	}
	if cfg.ShowEPSS {
		cols = append(cols, "EPSS", "EPSS %ile")
	}
	if cfg.ShowKEV {
		cols = append(cols, "KEV")
	}
	return cols
}

// suppressedRowCells returns the cell values for a single suppressed finding row.
func suppressedRowCells(mf *types.ModifiedFinding, cfg TableConfig) []string {
	v := &mf.Finding
	severity := v.Severity
	if cfg.IsTerminal {
		severity = colorizeSeverity(severity)
	}
	cols := []string{
		v.PkgName,
		v.VulnerabilityID,
		severity,
		mf.Status,
		mf.Statement,
		mf.Source,
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
	return cols
}

// hasVulnFindings reports whether any modified finding has Type "vulnerability".
func hasVulnFindings(findings []types.ModifiedFinding) bool {
	for i := range findings {
		if findings[i].Type == "vulnerability" {
			return true
		}
	}
	return false
}
