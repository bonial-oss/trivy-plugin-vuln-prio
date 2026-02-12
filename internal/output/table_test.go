// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
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
						Severity:         "CRITICAL",
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
						Severity:         "MEDIUM",
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
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines (header + 3 data rows)")

	// Verify header has all 8 columns.
	header := lines[0]
	for _, col := range []string{"CVE", "Severity", "Package", "Installed", "Risk", "EPSS", "EPSS %ile", "KEV"} {
		assert.Contains(t, header, col)
	}

	// Verify first data row has CVE-2024-1234 data.
	row1 := lines[1]
	for _, expected := range []string{"CVE-2024-1234", "CRITICAL", "libexample", "95.0", "0.97", "99.8", "YES"} {
		assert.Contains(t, row1, expected)
	}

	// Verify third row (CVE-2023-9999) has dashes for nil EPSS values.
	row3 := lines[3]
	assert.Contains(t, row3, "CVE-2023-9999")
	assert.Contains(t, row3, "NO")
}

func TestTableOutput_NoEPSS(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: false,
		ShowKEV:  true,
		ShowRisk: false, // Risk requires both EPSS and KEV
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	header := lines[0]

	// Should NOT have EPSS, EPSS %ile, or Risk columns.
	assert.NotContains(t, header, "EPSS")
	assert.NotContains(t, header, "Risk")

	// Should have KEV column.
	assert.Contains(t, header, "KEV")

	// Should have base columns.
	for _, col := range []string{"CVE", "Severity", "Package", "Installed"} {
		assert.Contains(t, header, col)
	}
}

func TestTableOutput_NoKEV(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  false,
		ShowRisk: false, // Risk requires both EPSS and KEV
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")
	header := lines[0]

	// Should NOT have KEV or Risk columns.
	assert.NotContains(t, header, "KEV")
	assert.NotContains(t, header, "Risk")

	// Should have EPSS columns.
	assert.Contains(t, header, "EPSS")
	assert.Contains(t, header, "EPSS %ile")
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
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines")

	// Risk descending: CVE-2024-1234 (95.0) > CVE-2023-5678 (31.5) > CVE-2023-9999 (0.0)
	assert.Contains(t, lines[1], "CVE-2024-1234")
	assert.Contains(t, lines[2], "CVE-2023-5678")
	assert.Contains(t, lines[3], "CVE-2023-9999")
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
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines")

	// Alphabetically ascending: CVE-2023-5678, CVE-2023-9999, CVE-2024-1234
	assert.Contains(t, lines[1], "CVE-2023-5678")
	assert.Contains(t, lines[2], "CVE-2023-9999")
	assert.Contains(t, lines[3], "CVE-2024-1234")
}

func TestTableOutput_PreserveOrder(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
		SortBy:   "", // preserve original order
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines")

	// Original order: CVE-2024-1234, CVE-2023-5678, CVE-2023-9999
	assert.Contains(t, lines[1], "CVE-2024-1234")
	assert.Contains(t, lines[2], "CVE-2023-5678")
	assert.Contains(t, lines[3], "CVE-2023-9999")
}

func TestTableOutput_SortBySeverity(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: false,
		ShowKEV:  false,
		ShowRisk: false,
		SortBy:   "severity",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines")

	// Severity descending: CRITICAL > HIGH > MEDIUM
	assert.Contains(t, lines[1], "CRITICAL")
	assert.Contains(t, lines[2], "HIGH")
	assert.Contains(t, lines[3], "MEDIUM")
}

func TestTableOutput_SortByEPSS(t *testing.T) {
	report := makeTestReport()
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  false,
		ShowRisk: false,
		SortBy:   "epss",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 4, "expected at least 4 lines")

	// EPSS descending: 0.97 > 0.42 > nil(0)
	assert.Contains(t, lines[1], "CVE-2024-1234")
	assert.Contains(t, lines[2], "CVE-2023-5678")
	assert.Contains(t, lines[3], "CVE-2023-9999")
}

func TestTableOutput_EmptyReport(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "empty:latest",
		ArtifactType:  "container_image",
		Results:       []types.Result{},
	}
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have just the header.
	assert.Len(t, lines, 1, "expected 1 line (header only)")
}

func TestTableOutput_NilVulnPrio(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test:latest",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target: "test:latest",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg",
						InstalledVersion: "1.0",
						Severity:         "HIGH",
						// VulnPrio is nil
					},
				},
			},
		},
	}
	cfg := TableConfig{
		ShowEPSS: true,
		ShowKEV:  true,
		ShowRisk: true,
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	require.GreaterOrEqual(t, len(lines), 2, "expected at least 2 lines")

	// Data row should have dashes for all enrichment columns.
	row := lines[1]
	assert.Contains(t, row, "CVE-2024-0001")
	// Count dashes - should have at least 3 (Risk, EPSS, EPSS %ile) + NO for KEV
	assert.GreaterOrEqual(t, strings.Count(row, "-"), 3, "expected at least 3 dashes for nil VulnPrio fields")
	assert.Contains(t, row, "NO")
}

func TestTableOutput_MultipleResults(t *testing.T) {
	report := &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "multi:latest",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target: "result1",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0001",
						PkgName:          "pkg1",
						InstalledVersion: "1.0",
						Severity:         "HIGH",
					},
				},
			},
			{
				Target: "result2",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2024-0002",
						PkgName:          "pkg2",
						InstalledVersion: "2.0",
						Severity:         "MEDIUM",
					},
				},
			},
		},
	}
	cfg := TableConfig{
		SortBy: "cve",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteTable(&buf, report, cfg))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should have header + 2 data rows (from both results).
	require.Len(t, lines, 3, "expected 3 lines")

	assert.Contains(t, lines[1], "CVE-2024-0001")
	assert.Contains(t, lines[2], "CVE-2024-0002")
}
