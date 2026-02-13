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
	for _, col := range []string{"Library", "Vulnerability", "Severity", "Status",
		"Installed Version", "Fixed Version", "Title", "Risk", "EPSS", "EPSS %ile", "KEV"} {
		assert.Contains(t, output, col)
	}

	// Verify data content.
	for _, expected := range []string{
		"CVE-2024-1234", "CRITICAL", "libexample", "1.0.0", "1.0.1", "95.0", "0.97", "99.8", "YES",
		"CVE-2023-5678", "HIGH", "libanother",
		"CVE-2023-9999", "MEDIUM", "libunknown",
	} {
		assert.Contains(t, output, expected)
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

	assert.NotContains(t, output, "EPSS")
	assert.NotContains(t, output, "Risk")
	assert.Contains(t, output, "KEV")
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

	assert.NotContains(t, output, "KEV")
	assert.Contains(t, output, "EPSS")
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

	output := buf.String()
	assertOrder(t, output, "CVE-2024-1234", "CVE-2023-5678", "CVE-2023-9999")
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

	output := buf.String()
	assertOrder(t, output, "CVE-2023-5678", "CVE-2023-9999", "CVE-2024-1234")
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

	output := buf.String()
	assertOrder(t, output, "CVE-2024-1234", "CVE-2023-5678", "CVE-2023-9999")
}

func TestTableOutput_SortBySeverity(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{SortBy: "severity"}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	// CRITICAL (CVE-2024-1234) > HIGH (CVE-2023-5678) > MEDIUM (CVE-2023-9999).
	assertOrder(t, output, "CVE-2024-1234", "CVE-2023-5678", "CVE-2023-9999")
}

func TestTableOutput_SortByEPSS(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{ShowEPSS: true, SortBy: "epss"}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	// EPSS: 0.97 > 0.42 > nil.
	assertOrder(t, output, "CVE-2024-1234", "CVE-2023-5678", "CVE-2023-9999")
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

	output := buf.String()
	assert.Contains(t, output, "CVE-2024-0001")
	assert.Contains(t, output, "NO")
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

	// Both title and URL should appear in output.
	assert.Contains(t, output, "Example vulnerability")
	assert.Contains(t, output, "https://avd.aquasec.com/nvd/cve-2024-0001")
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
		HideSuppressed: false,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Should have "Suppressed Vulnerabilities (Total: 1)" header with underline.
	assert.Contains(t, output, "Suppressed Vulnerabilities (Total: 1)")
	expectedUnderline := strings.Repeat("=", len("Suppressed Vulnerabilities (Total: 1)"))
	assert.Contains(t, output, expectedUnderline)

	// Should have 2 box tables (regular + suppressed).
	assert.Equal(t, 2, strings.Count(output, "┌"))

	// Suppressed table should have correct columns.
	assert.Contains(t, output, "Statement")
	assert.Contains(t, output, "Source")

	// Suppressed data should contain the finding.
	for _, expected := range []string{"CVE-2024-0002", "Not applicable", ".trivyignore"} {
		assert.Contains(t, output, expected)
	}
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
	cfg := TableConfig{HideSuppressed: true}

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
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Target header should appear.
	assert.Contains(t, output, "suppressed-only (npm)")

	// Should have suppressed section with total.
	assert.Contains(t, output, "Suppressed Vulnerabilities (Total: 1)")

	// Only 1 box table (suppressed only, no regular vulns table).
	assert.Equal(t, 1, strings.Count(output, "┌"))

	// Data should contain the suppressed finding.
	assert.Contains(t, output, "CVE-2024-0003")
	assert.Contains(t, output, "Fixed in build")
}

func TestTableOutput_AutoMerge(t *testing.T) {
	// Two vulns with the same severity should have auto-merged severity cells.
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg1", InstalledVersion: "1.0", Severity: "HIGH"},
					{VulnerabilityID: "CVE-2024-0002", PkgName: "pkg2", InstalledVersion: "2.0", Severity: "HIGH"},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// With auto-merge, "HIGH" should appear once in data (merged cell).
	// Count occurrences in data rows only (after header).
	headerIdx := strings.Index(output, "Severity")
	afterHeader := output[headerIdx+1:]
	// "HIGH" appears once in header, and once in the merged data cell.
	assert.Equal(t, 1, strings.Count(afterHeader, "HIGH"))
}

func TestTableOutput_RowSeparators(t *testing.T) {
	// With SetRowLines(true), row separators should appear between data rows.
	report := &types.Report{
		SchemaVersion: 2,
		Results: []types.Result{
			{
				Target: "test",
				Vulnerabilities: []types.Vulnerability{
					{VulnerabilityID: "CVE-2024-0001", PkgName: "pkg1", InstalledVersion: "1.0", Severity: "HIGH"},
					{VulnerabilityID: "CVE-2024-0002", PkgName: "pkg2", InstalledVersion: "2.0", Severity: "MEDIUM"},
				},
			},
		},
	}
	cfg := TableConfig{}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()

	// Should have row separator lines (├) between data rows.
	// With 2 rows: 1 header sep + 1 row sep = at least 2 ├ lines.
	assert.GreaterOrEqual(t, strings.Count(output, "├"), 2)
}

// assertOrder verifies that the given strings appear in order in the output.
func assertOrder(t *testing.T, output string, items ...string) {
	t.Helper()
	prev := -1
	for _, item := range items {
		idx := strings.Index(output, item)
		require.NotEqual(t, -1, idx, "missing %q in output", item)
		assert.Greater(t, idx, prev, "%q should appear after previous item", item)
		prev = idx
	}
}
