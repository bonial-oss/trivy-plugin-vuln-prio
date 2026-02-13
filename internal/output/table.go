// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const (
	maxTitleWords     = 12
	maxTitleWidth     = 44
	maxStatementWidth = 80
)

// TableConfig controls which columns are displayed and how rows are sorted.
type TableConfig struct {
	ShowEPSS       bool
	ShowKEV        bool
	ShowRisk       bool   // true only when both EPSS and KEV enabled
	SortBy         string // "risk", "epss", "severity", "cve", "" (preserve order)
	HideSuppressed bool   // exclude suppressed vulnerabilities section
}

// vulnRow holds a reference to a vulnerability for table rendering.
type vulnRow struct {
	vuln  *types.Vulnerability
	index int // original index for stable sort
}

// WriteTable writes an enriched report as a box-drawn table grouped by target.
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

		writeTargetHeader(w, result)

		if len(vulns) > 0 {
			rows := make([]vulnRow, len(vulns))
			for j := range vulns {
				rows[j] = vulnRow{vuln: &vulns[j], index: j}
			}
			sortRows(rows, cfg.SortBy)
			writeBoxTable(w, rows, cfg)
		}

		if hasSuppressed {
			if len(vulns) > 0 {
				fmt.Fprintln(w)
			}
			fmt.Fprintln(w, "Suppressed Vulnerabilities")
			writeSuppressedTable(w, result.ExperimentalModifiedFindings, cfg)
		}
	}

	if first {
		writeBoxTable(w, nil, cfg)
	}

	return nil
}

// writeTargetHeader writes the target name, separator, and severity summary.
func writeTargetHeader(w io.Writer, result *types.Result) {
	target := result.Target
	if result.Type != "" {
		target = fmt.Sprintf("%s (%s)", result.Target, result.Type)
	}
	fmt.Fprintln(w, target)
	fmt.Fprintln(w, strings.Repeat("=", utf8.RuneCountInString(target)))
	fmt.Fprintln(w, severitySummary(result.Vulnerabilities))
	fmt.Fprintln(w)
}

// columnWidthFn returns the max display width for column colIndex, or 0 for content-driven.
type columnWidthFn func(colIndex int, headers []string) int

// vulnColumnWidth caps the Title column to keep the overall table width manageable.
func vulnColumnWidth(colIndex int, headers []string) int {
	if colIndex < len(headers) && headers[colIndex] == "Title" {
		return maxTitleWidth
	}
	return 0
}

// suppressedColumnWidth caps the Statement column for readability.
func suppressedColumnWidth(colIndex int, headers []string) int {
	if colIndex < len(headers) && headers[colIndex] == "Statement" {
		return maxStatementWidth
	}
	return 0
}

// writeBoxTable renders a box-drawn table for vulnerability rows.
func writeBoxTable(w io.Writer, rows []vulnRow, cfg TableConfig) {
	headers := headerNames(cfg)
	var cellRows [][]string
	for _, row := range rows {
		cellRows = append(cellRows, rowCells(row.vuln, cfg))
	}
	renderBoxTable(w, headers, cellRows, vulnColumnWidth)
}

// renderBoxTable draws a box-drawn table with the given headers, cell data, and width function.
func renderBoxTable(w io.Writer, headers []string, cellRows [][]string, maxWidth columnWidthFn) {
	numCols := len(headers)

	// Compute column widths from headers and data.
	widths := make([]int, numCols)
	for i, h := range headers {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, cells := range cellRows {
		for i, cell := range cells {
			lines := wrapText(cell, maxWidth(i, headers))
			for _, line := range lines {
				if n := utf8.RuneCountInString(line); n > widths[i] {
					widths[i] = n
				}
			}
		}
	}

	// Draw top border.
	fmt.Fprintln(w, borderLine(widths, "┌", "┬", "┐"))

	// Draw header row (centered).
	fmt.Fprintln(w, dataLine(widths, headers, true))

	// Draw header separator.
	fmt.Fprintln(w, borderLine(widths, "├", "┼", "┤"))

	// Draw data rows with word wrapping.
	for _, cells := range cellRows {
		wrapped := make([][]string, numCols)
		maxLines := 1
		for i, cell := range cells {
			wrapped[i] = wrapText(cell, widths[i])
			if len(wrapped[i]) > maxLines {
				maxLines = len(wrapped[i])
			}
		}
		for line := 0; line < maxLines; line++ {
			lineCells := make([]string, numCols)
			for i := range lineCells {
				if line < len(wrapped[i]) {
					lineCells[i] = wrapped[i][line]
				}
			}
			fmt.Fprintln(w, dataLine(widths, lineCells, false))
		}
	}

	// Draw bottom border.
	fmt.Fprintln(w, borderLine(widths, "└", "┴", "┘"))
}

// borderLine builds a horizontal border like ┌────┬────┬────┐.
func borderLine(widths []int, left, mid, right string) string {
	var b strings.Builder
	b.WriteString(left)
	for i, w := range widths {
		if i > 0 {
			b.WriteString(mid)
		}
		b.WriteString(strings.Repeat("─", w+2)) // 1 padding each side
	}
	b.WriteString(right)
	return b.String()
}

// dataLine builds a row like │ val │ val │ val │.
// If center is true, values are centered; otherwise left-aligned.
func dataLine(widths []int, cells []string, center bool) string {
	var b strings.Builder
	b.WriteString("│")
	for i, w := range widths {
		val := ""
		if i < len(cells) {
			val = cells[i]
		}
		n := utf8.RuneCountInString(val)
		if center {
			totalPad := w - n
			leftPad := totalPad / 2
			rightPad := totalPad - leftPad
			b.WriteString(" ")
			b.WriteString(strings.Repeat(" ", leftPad))
			b.WriteString(val)
			b.WriteString(strings.Repeat(" ", rightPad))
			b.WriteString(" ")
		} else {
			b.WriteString(" ")
			b.WriteString(val)
			b.WriteString(strings.Repeat(" ", w-n))
			b.WriteString(" ")
		}
		b.WriteString("│")
	}
	return b.String()
}

// wrapText splits text into lines of at most maxWidth runes.
// Embedded newlines are respected as hard breaks.
// If maxWidth is 0 or the text fits on one line, returns a single-element slice.
func wrapText(text string, maxWidth int) []string {
	// First, split on hard newlines.
	paragraphs := strings.Split(text, "\n")

	if maxWidth <= 0 {
		return paragraphs
	}

	var lines []string
	for _, para := range paragraphs {
		lines = append(lines, wrapLine(para, maxWidth)...)
	}
	return lines
}

// wrapLine wraps a single line of text to maxWidth runes with word-boundary breaking.
func wrapLine(text string, maxWidth int) []string {
	if utf8.RuneCountInString(text) <= maxWidth {
		return []string{text}
	}

	var lines []string
	runes := []rune(text)
	for len(runes) > 0 {
		end := maxWidth
		if end > len(runes) {
			end = len(runes)
		}

		// Try to break at a space for cleaner wrapping.
		if end < len(runes) {
			spaceIdx := -1
			for i := end - 1; i >= end/2; i-- {
				if runes[i] == ' ' {
					spaceIdx = i
					break
				}
			}
			if spaceIdx > 0 {
				lines = append(lines, string(runes[:spaceIdx]))
				runes = runes[spaceIdx+1:]
				continue
			}
		}

		lines = append(lines, string(runes[:end]))
		runes = runes[end:]
	}
	return lines
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
	cols := []string{
		v.PkgName,
		v.VulnerabilityID,
		v.Severity,
		extraString(v, "Status"),
		v.InstalledVersion,
		v.FixedVersion,
		titleWithURL(v),
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
func titleWithURL(v *types.Vulnerability) string {
	title := extraString(v, "Title")
	title = truncateWords(title, maxTitleWords)
	url := extraString(v, "PrimaryURL")
	if url != "" {
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
	cols := []string{
		v.PkgName,
		v.VulnerabilityID,
		v.Severity,
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

// writeSuppressedTable renders a box-drawn table for suppressed findings.
func writeSuppressedTable(w io.Writer, findings []types.ModifiedFinding, cfg TableConfig) {
	headers := suppressedHeaderNames(cfg)
	var cellRows [][]string
	for i := range findings {
		if findings[i].Type != "vulnerability" {
			continue
		}
		cellRows = append(cellRows, suppressedRowCells(&findings[i], cfg))
	}
	renderBoxTable(w, headers, cellRows, suppressedColumnWidth)
}
