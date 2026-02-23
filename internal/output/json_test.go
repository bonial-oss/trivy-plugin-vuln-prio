// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package output

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

func TestWriteJSON_Report(t *testing.T) {
	score := 0.85
	percentile := 0.95
	risk := 8.5

	report := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "myimage:latest",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target: "myimage:latest (alpine 3.18)",
				Class:  "os-pkgs",
				Type:   "alpine",
				Vulnerabilities: []types.Vulnerability{
					{
						VulnerabilityID:  "CVE-2023-0001",
						PkgName:          "openssl",
						InstalledVersion: "3.0.0",
						FixedVersion:     "3.0.1",
						Severity:         "HIGH",
						VulnPrio: &types.VulnPrio{
							Risk: &risk,
							EPSS: &types.EPSSData{
								Score:      &score,
								Percentile: &percentile,
							},
							KEV: &types.KEVData{
								Listed:    true,
								DateAdded: "2024-01-15",
							},
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, report))

	output := buf.Bytes()

	// Verify it is valid JSON.
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(output, &parsed))

	// Verify indentation (should start with "{\n  ").
	assert.True(t, bytes.HasPrefix(output, []byte("{\n  ")), "output is not indented as expected")

	// Verify SchemaVersion is present.
	assert.Contains(t, parsed, "SchemaVersion")

	// Parse Results to find VulnPrio.
	var results []json.RawMessage
	require.NoError(t, json.Unmarshal(parsed["Results"], &results))
	require.Len(t, results, 1)

	var resultObj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(results[0], &resultObj))

	var vulns []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resultObj["Vulnerabilities"], &vulns))
	require.Len(t, vulns, 1)

	require.Contains(t, vulns[0], "VulnPrio")
	vulnPrioRaw := vulns[0]["VulnPrio"]

	var vp types.VulnPrio
	require.NoError(t, json.Unmarshal(vulnPrioRaw, &vp))

	require.NotNil(t, vp.Risk)
	assert.Equal(t, 8.5, *vp.Risk)

	require.NotNil(t, vp.EPSS)
	require.NotNil(t, vp.EPSS.Score)
	assert.Equal(t, 0.85, *vp.EPSS.Score)

	require.NotNil(t, vp.KEV)
	assert.True(t, vp.KEV.Listed)
}

func TestWriteJSON_SARIF(t *testing.T) {
	report := types.SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []types.SARIFRun{
			{
				Tool: json.RawMessage(`{"driver":{"name":"Trivy"}}`),
				Results: []types.SARIFResult{
					{
						RuleID:  "CVE-2023-0001",
						Level:   "error",
						Message: json.RawMessage(`{"text":"A vulnerability"}`),
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, report))

	output := buf.Bytes()

	// Verify it is valid JSON.
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(output, &parsed))

	// Verify key SARIF fields are present.
	assert.Contains(t, parsed, "$schema")
	assert.Contains(t, parsed, "version")
	assert.Contains(t, parsed, "runs")

	// Verify indentation.
	assert.True(t, bytes.HasPrefix(output, []byte("{\n  ")), "output is not indented as expected")
}

func TestWriteJSON_EscapeHTML(t *testing.T) {
	// Verify SetEscapeHTML(false) works: angle brackets should not be escaped.
	data := map[string]string{
		"url": "https://example.com/path?a=1&b=2",
	}

	var buf bytes.Buffer
	require.NoError(t, WriteJSON(&buf, data))

	output := buf.String()
	assert.NotContains(t, output, `\u0026`)
}
