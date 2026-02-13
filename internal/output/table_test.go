// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// Helper to create a float64 pointer.
func floatPtr(v float64) *float64 {
	return &v
}

// makeTestReport builds a report with 3 vulnerabilities for table tests.
func makeTestReport() *types.Report {
	return &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test:latest",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target: "test:latest",
				Class:  "os-pkgs",
				Type:   "debian",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-1234",
						PkgName:          "libexample",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						Severity:         "CRITICAL",
						Extras: map[string]json.RawMessage{
							"Status": json.RawMessage(`"fixed"`),
							"Title":  json.RawMessage(`"Example critical vulnerability"`),
						},
						VulnPrio: &types.VulnPrio{
							Risk: floatPtr(95.0),
							EPSS: &types.EPSSData{
								Score:      floatPtr(0.97),
								Percentile: floatPtr(0.998),
							},
							KEV: &types.KEVData{
								Listed:    true,
								DateAdded: "2024-01-15",
							},
						},
					},
					{
						VulnerabilityID:  "CVE-2023-5678",
						PkgName:          "libanother",
						InstalledVersion: "2.0.0",
						Severity:         "HIGH",
						Extras: map[string]json.RawMessage{
							"Status": json.RawMessage(`"affected"`),
							"Title":  json.RawMessage(`"Another high vulnerability"`),
						},
						VulnPrio: &types.VulnPrio{
							Risk: floatPtr(31.5),
							EPSS: &types.EPSSData{
								Score:      floatPtr(0.42),
								Percentile: floatPtr(0.873),
							},
							KEV: &types.KEVData{
								Listed: false,
							},
						},
					},
					{
						VulnerabilityID:  "CVE-2023-9999",
						PkgName:          "libunknown",
						InstalledVersion: "3.0.0",
						FixedVersion:     "3.0.1",
						Severity:         "MEDIUM",
						Extras: map[string]json.RawMessage{
							"Status": json.RawMessage(`"fixed"`),
							"Title":  json.RawMessage(`"Medium severity issue"`),
						},
						VulnPrio: &types.VulnPrio{
							Risk: floatPtr(0.0),
							EPSS: &types.EPSSData{},
							KEV: &types.KEVData{
								Listed: false,
							},
						},
					},
				},
			},
		},
	}
}

func TestTableOutput_AllColumns(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Verify target header.
	assert.Contains(t, output, "test:latest (debian)")
	assert.Contains(t, output, "===")
	assert.Contains(t, output, "Total: 3")
	assert.Contains(t, output, "CRITICAL: 1")

	// Verify box-drawing characters.
	for _, ch := range []string{"┌", "┘", "│", "├"} {
		assert.Contains(t, output, ch)
	}

	// Verify header has all columns.
	headerLine := findHeaderLine(output)
	for _, col := range []string{"Library", "Vulnerability", "Severity", "Status", "Installed Version", "Fixed Version", "Title", "Risk", "EPSS", "EPSS %ile", "KEV"} {
		assert.Contains(t, headerLine, col)
	}

	// Verify data content.
	dataRows := findDataRows(output)
	require.GreaterOrEqual(t, len(dataRows), 3, "expected at least 3 data rows")

	row1 := dataRows[0]
	for _, expected := range []string{"CVE-2024-1234", "CRITICAL", "libexample", "fixed", "1.0.0", "1.0.1", "95.0", "0.97", "99.8", "YES"} {
		assert.Contains(t, row1, expected)
	}
}

func TestTableOutput_NoEPSS(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: false,
		ShowKEV:  true,
		ShowRisk: false,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	header := findHeaderLine(output)

	assert.NotContains(t, header, "EPSS")
	assert.NotContains(t, header, "Risk")
	assert.Contains(t, header, "KEV")
}

func TestTableOutput_NoKEV(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  false,
		ShowRisk: false,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	header := findHeaderLine(output)

	assert.NotContains(t, header, "KEV")
	assert.Contains(t, header, "EPSS")
}

func TestTableOutput_SortByRisk(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
		SortBy:   "risk",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 3, "expected 3 data rows")

	assert.Contains(t, dataRows[0], "CVE-2024-1234")
	assert.Contains(t, dataRows[1], "CVE-2023-5678")
	assert.Contains(t, dataRows[2], "CVE-2023-9999")
}

func TestTableOutput_SortByCVE(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
		SortBy:   "cve",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 3, "expected 3 data rows")

	assert.Contains(t, dataRows[0], "CVE-2023-5678")
	assert.Contains(t, dataRows[1], "CVE-2023-9999")
	assert.Contains(t, dataRows[2], "CVE-2024-1234")
}

func TestTableOutput_PreserveOrder(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
		SortBy:   "",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 3, "expected 3 data rows")

	assert.Contains(t, dataRows[0], "CVE-2024-1234")
	assert.Contains(t, dataRows[1], "CVE-2023-5678")
	assert.Contains(t, dataRows[2], "CVE-2023-9999")
}

func TestTableOutput_SortBySeverity(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{SortBy: "severity"}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 3, "expected 3 data rows")

	assert.Contains(t, dataRows[0], "CRITICAL")
	assert.Contains(t, dataRows[1], "HIGH")
	assert.Contains(t, dataRows[2], "MEDIUM")
}

func TestTableOutput_SortByEPSS(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{ShowEPSS: true, SortBy: "epss"}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 3, "expected 3 data rows")

	assert.Contains(t, dataRows[0], "CVE-2024-1234")
	assert.Contains(t, dataRows[1], "CVE-2023-5678")
	assert.Contains(t, dataRows[2], "CVE-2023-9999")
}

func TestTableOutput_EmptyReport(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results:       []types.Result{},
	}
	cfg := TableConfig{ShowEPSS: true, ShowKEV: true, ShowRisk: true}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Should have box structure with header only (no data rows).
	assert.Contains(t, output, "┌")
	assert.Contains(t, output, "Library")
	// No target headers.
	assert.NotContains(t, output, "===")
}

func TestTableOutput_NilVulnPrio(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test:latest",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg",
						InstalledVersion: "1.0",
						Severity:         "HIGH",
					},
				},
			},
		},
	}
	cfg := TableConfig{ShowEPSS: true, ShowKEV: true, ShowRisk: true}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	dataRows := findDataRows(buf.String())
	require.GreaterOrEqual(t, len(dataRows), 1, "expected at least 1 data row")

	row := dataRows[0]
	assert.Contains(t, row, "CVE-2024-0001")
	assert.Contains(t, row, "NO")
}

func TestTableOutput_MultipleResults(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "result1",
				Type:   "debian",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg1", InstalledVersion: "1.0", Severity: "HIGH"},
				},
			},
			{
				Target: "result2",
				Type:   "yarn",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0002", PkgName: "pkg2", InstalledVersion: "2.0", Severity: "MEDIUM"},
				},
			},
		},
	}
	cfg := TableConfig{SortBy: "cve"}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	assert.Contains(t, output, "result1 (debian)")
	assert.Contains(t, output, "result2 (yarn)")
	assert.Contains(t, output, "Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 0)")
	assert.Contains(t, output, "Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)")

	// Each target should have its own box table.
	assert.Equal(t, 2, strings.Count(output, "┌"))
}

func TestTableOutput_TargetWithoutType(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test:latest",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg", InstalledVersion: "1.0", Severity: "LOW"},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(output, "\n")

	assert.NotContains(t, lines[0], "(")
	assert.Contains(t, lines[0], "test:latest")
}

func TestTableOutput_TitleTruncation(t *testing.T) {
	longTitle := "This is a very long vulnerability title that exceeds the maximum word count and should be truncated with ellipsis at the end"
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg",
						InstalledVersion: "1.0",
						Severity:         "LOW",
						Extras: map[string]json.RawMessage{
							"Title": json.RawMessage(`"` + longTitle + `"`),
						},
					},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Title should be truncated to 12 words with "..."
	assert.Contains(t, output, "...")
	// Full title should not appear.
	assert.NotContains(t, output, "at the end")
}

func TestTableOutput_TitleWithURL(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg",
						InstalledVersion: "1.0",
						Severity:         "LOW",
						Extras: map[string]json.RawMessage{
							"Title":      json.RawMessage(`"Example vulnerability"`),
							"PrimaryURL": json.RawMessage(`"https://avd.aquasec.com/nvd/cve-2024-0001"`),
						},
					},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	dataRows := findDataRows(output)

	// Title + URL should produce multiple visual lines.
	require.GreaterOrEqual(t, len(dataRows), 2, "expected URL on separate line")

	// First line should have CVE and title.
	assert.Contains(t, dataRows[0], "CVE-2024-0001")
	assert.Contains(t, dataRows[0], "Example vulnerability")

	// Second line should contain the URL.
	assert.Contains(t, dataRows[1], "https://avd.aquasec.com/nvd/cve-2024-0001")
}

func TestTableOutput_ResultsWithNoVulns(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{Target: "clean-target", Type: "debian"},
			{
				Target: "vuln-target",
				Type:   "yarn",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg", InstalledVersion: "1.0", Severity: "LOW"},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	assert.NotContains(t, output, "clean-target")
	assert.Contains(t, output, "vuln-target (yarn)")
}

func TestWrapText(t *testing.T) {
	tests := []struct {
		text     string
		maxWidth int
		want     int // expected number of lines
	}{
		{"short", 10, 1},
		{"", 10, 1},
		{"hello world foo bar", 10, 3},
		{"abcdefghij", 5, 2},
		{"no wrap needed", 0, 1},
	}
	for _, tt := range tests {
		lines := wrapText(tt.text, tt.maxWidth)
		assert.Len(t, lines, tt.want, "wrapText(%q, %d)", tt.text, tt.maxWidth)
	}
}

func TestVulnColumnWidth_TitleColumn(t *testing.T) {
	headers := headerNames(TableConfig{})
	for i, h := range headers {
		w := vulnColumnWidth(i, headers)
		if h == "Title" {
			assert.Equal(t, maxTitleWidth, w, "vulnColumnWidth for Title")
		} else {
			assert.Equal(t, 0, w, "vulnColumnWidth(%d, %q)", i, h)
		}
	}
}

func TestSuppressedColumnWidth_StatementColumn(t *testing.T) {
	headers := suppressedHeaderNames(TableConfig{})
	for i, h := range headers {
		w := suppressedColumnWidth(i, headers)
		if h == "Statement" {
			assert.Equal(t, maxStatementWidth, w, "suppressedColumnWidth for Statement")
		} else {
			assert.Equal(t, 0, w, "suppressedColumnWidth(%d, %q)", i, h)
		}
	}
}

func TestTableOutput_TitleWrapping(t *testing.T) {
	// URL longer than maxTitleWidth should wrap across multiple lines.
	longURL := "https://avd.aquasec.com/nvd/cve-2024-0001-very-long-path-segment"
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg",
						InstalledVersion: "1.0",
						Severity:         "LOW",
						Extras: map[string]json.RawMessage{
							"Title":      json.RawMessage(`"Short title"`),
							"PrimaryURL": json.RawMessage(`"` + longURL + `"`),
						},
					},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	dataRows := findDataRows(output)

	// Should have multiple visual lines: title line + wrapped URL lines.
	assert.GreaterOrEqual(t, len(dataRows), 3, "expected at least 3 visual lines (title + wrapped URL)")

	// Verify no data row exceeds maxTitleWidth in the Title column.
	headers := headerNames(TableConfig{})
	titleIdx := -1
	for i, h := range headers {
		if h == "Title" {
			titleIdx = i
			break
		}
	}
	require.GreaterOrEqual(t, titleIdx, 0, "Title column not found in headers")
	for _, row := range dataRows {
		// Extract Title column content by splitting on │.
		cols := strings.Split(row, "│")
		if len(cols) > titleIdx+1 {
			titleCell := strings.TrimSpace(cols[titleIdx+1]) // +1 because first element is empty
			assert.LessOrEqual(t, len([]rune(titleCell)), maxTitleWidth, "Title cell exceeds maxTitleWidth: %q", titleCell)
		}
	}
}

func TestTableOutput_SuppressedSection(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test:latest",
				Type:   "debian",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg1", InstalledVersion: "1.0", Severity: "HIGH"},
				},
				ExperimentalModifiedFindings: []types.ModifiedFinding{
					{
						Type:      "vulnerability",
						Status:    "ignored",
						Statement: "Not applicable",
						Source:    ".trivyignore",
						Finding: types.Vulnerability{
							VulnerabilityID:  "CVE-2024-0002",
							PkgName:          "pkg2",
							InstalledVersion: "2.0",
							Severity:         "MEDIUM",
							VulnPrio: &types.VulnPrio{
								Risk: floatPtr(5.0),
								EPSS: &types.EPSSData{Score: floatPtr(0.1), Percentile: floatPtr(0.5)},
								KEV:  &types.KEVData{Listed: false},
							},
						},
					},
				},
			},
		},
	}
	cfg := TableConfig{
		ShowEPSS:       true,
		ShowKEV:        true,
		ShowRisk:       true,
		ShowSuppressed: true,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Should have "Suppressed Vulnerabilities" header.
	assert.Contains(t, output, "Suppressed Vulnerabilities")

	// Should have 2 box tables (regular + suppressed).
	assert.Equal(t, 2, strings.Count(output, "┌"))

	// Find the suppressed table header.
	lines := strings.Split(output, "\n")
	var suppressedHeader string
	afterSuppressedLabel := false
	for _, line := range lines {
		if strings.Contains(line, "Suppressed Vulnerabilities") {
			afterSuppressedLabel = true
			continue
		}
		if afterSuppressedLabel && strings.Contains(line, "Library") && strings.Contains(line, "Statement") {
			suppressedHeader = line
			break
		}
	}

	require.NotEmpty(t, suppressedHeader, "could not find suppressed table header")

	// Suppressed header should have Statement and Source columns, not Title/Fixed Version.
	for _, col := range []string{"Library", "Vulnerability", "Severity", "Status", "Statement", "Source", "Risk", "EPSS", "KEV"} {
		assert.Contains(t, suppressedHeader, col)
	}
	for _, col := range []string{"Title", "Fixed Version", "Installed Version"} {
		assert.NotContains(t, suppressedHeader, col)
	}

	// Suppressed data should contain the finding.
	assert.Contains(t, output, "CVE-2024-0002")
	assert.Contains(t, output, "Not applicable")
	assert.Contains(t, output, ".trivyignore")
}

func TestTableOutput_SuppressedHidden(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test:latest",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg1", InstalledVersion: "1.0", Severity: "HIGH"},
				},
				ExperimentalModifiedFindings: []types.ModifiedFinding{
					{
						Type:   "vulnerability",
						Status: "ignored",
						Finding: types.Vulnerability{
							VulnerabilityID: "CVE-2024-0002",
							PkgName:         "pkg2",
							Severity:        "MEDIUM",
						},
					},
				},
			},
		},
	}
	// ShowSuppressed=false (default).
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	assert.NotContains(t, output, "Suppressed")
	assert.NotContains(t, output, "CVE-2024-0002")
}

func TestTableOutput_SuppressedOnlyResult(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "suppressed-only",
				Type:   "npm",
				ExperimentalModifiedFindings: []types.ModifiedFinding{
					{
						Type:      "vulnerability",
						Status:    "not_affected",
						Statement: "Fixed in build",
						Source:    "VEX",
						Finding: types.Vulnerability{
							VulnerabilityID:  "CVE-2024-0003",
							PkgName:          "pkg3",
							InstalledVersion: "3.0",
							Severity:         "LOW",
						},
					},
				},
			},
		},
	}
	cfg := TableConfig{ShowSuppressed: true}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Target header should appear.
	assert.Contains(t, output, "suppressed-only (npm)")

	// Should have suppressed section.
	assert.Contains(t, output, "Suppressed Vulnerabilities")

	// Only 1 box table (suppressed only, no regular vulns table).
	assert.Equal(t, 1, strings.Count(output, "┌"))

	// Data should contain the suppressed finding.
	assert.Contains(t, output, "CVE-2024-0003")
	assert.Contains(t, output, "Fixed in build")
}

// findHeaderLine finds the table header line in box-drawn output.
func findHeaderLine(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Library") && strings.Contains(line, "Vulnerability") {
			return line
		}
	}
	return ""
}

// findDataRows extracts data rows (│ ... │ lines after the header separator ├...┤).
func findDataRows(output string) []string {
	lines := strings.Split(output, "\n")
	var dataRows []string
	afterSep := false
	for _, line := range lines {
		if strings.HasPrefix(line, "├") {
			afterSep = true
			continue
		}
		if afterSep {
			if strings.HasPrefix(line, "└") {
				// Bottom border — reset for next table.
				afterSep = false
				continue
			}
			if strings.HasPrefix(line, "│") {
				dataRows = append(dataRows, line)
			}
		}
	}
	return dataRows
}
