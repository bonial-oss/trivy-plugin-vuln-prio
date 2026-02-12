// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIFResult_RoundTrip_PreservesExtras(t *testing.T) {
	input := `{
		"ruleId": "CVE-2023-1234",
		"level": "error",
		"message": {"text": "Buffer overflow in libfoo"},
		"locations": [
			{
				"physicalLocation": {
					"artifactLocation": {"uri": "package-lock.json"}
				}
			}
		],
		"fingerprints": {"primaryLocationLineHash": "abc123"}
	}`

	var r SARIFResult
	require.NoError(t, json.Unmarshal([]byte(input), &r))

	// Verify known fields.
	assert.Equal(t, "CVE-2023-1234", r.RuleID)
	assert.Equal(t, "error", r.Level)
	assert.NotNil(t, r.Message)

	// Verify extras captured unknown fields.
	assert.Contains(t, r.Extras, "locations")
	assert.Contains(t, r.Extras, "fingerprints")

	// Add properties (as plugin would do).
	r.Properties = map[string]json.RawMessage{
		"vulnPrio": json.RawMessage(`{"risk": 7.5}`),
	}

	// Re-marshal.
	out, err := json.Marshal(r)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	// All original fields must survive.
	expectedKeys := []string{
		"ruleId", "level", "message", "locations", "fingerprints", "properties",
	}
	for _, key := range expectedKeys {
		assert.Contains(t, result, key)
	}

	// Verify properties content.
	var props map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["properties"], &props))
	assert.Contains(t, props, "vulnPrio")
}

func TestSARIFRun_RoundTrip_PreservesExtras(t *testing.T) {
	input := `{
		"tool": {
			"driver": {
				"name": "Trivy",
				"version": "0.50.0"
			}
		},
		"results": [
			{
				"ruleId": "CVE-2023-0001",
				"level": "warning",
				"message": {"text": "Some vuln"}
			}
		],
		"columnKind": "utf16CodeUnits",
		"originalUriBaseIds": {
			"ROOTPATH": {"uri": "file:///workspace/"}
		}
	}`

	var run SARIFRun
	require.NoError(t, json.Unmarshal([]byte(input), &run))

	// Verify known fields.
	assert.NotNil(t, run.Tool)
	require.Len(t, run.Results, 1)
	assert.Equal(t, "CVE-2023-0001", run.Results[0].RuleID)

	// Verify extras.
	assert.Contains(t, run.Extras, "columnKind")
	assert.Contains(t, run.Extras, "originalUriBaseIds")

	// Re-marshal.
	out, err := json.Marshal(run)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	expectedKeys := []string{
		"tool", "results", "columnKind", "originalUriBaseIds",
	}
	for _, key := range expectedKeys {
		assert.Contains(t, result, key)
	}
}

func TestSARIFReport_FullRoundTrip(t *testing.T) {
	input := `{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {"driver": {"name": "Trivy"}},
				"results": [
					{
						"ruleId": "CVE-2024-0001",
						"level": "error",
						"message": {"text": "Critical vuln"},
						"locations": [{"physicalLocation": {"artifactLocation": {"uri": "go.sum"}}}]
					}
				],
				"columnKind": "utf16CodeUnits"
			}
		]
	}`

	var report SARIFReport
	require.NoError(t, json.Unmarshal([]byte(input), &report))

	assert.NotEmpty(t, report.Schema)
	assert.Equal(t, "2.1.0", report.Version)
	require.Len(t, report.Runs, 1)

	run := report.Runs[0]
	require.Len(t, run.Results, 1)

	// Add properties to the result.
	run.Results[0].Properties = map[string]json.RawMessage{
		"vulnPrio": json.RawMessage(`{"risk": 9.0}`),
	}
	report.Runs[0] = run

	// Marshal and verify.
	out, err := json.Marshal(report)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	assert.Contains(t, result, "$schema")
	assert.Contains(t, result, "version")

	// Parse runs to verify structure.
	var runs []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result["runs"], &runs))

	// columnKind should survive.
	assert.Contains(t, runs[0], "columnKind")

	// Parse results.
	var results []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(runs[0]["results"], &results))

	// locations and properties should both be present.
	assert.Contains(t, results[0], "locations")
	assert.Contains(t, results[0], "properties")
}

func TestSARIFResult_EmptyExtras(t *testing.T) {
	input := `{
		"ruleId": "CVE-2023-0001",
		"level": "warning",
		"message": {"text": "Some vuln"}
	}`

	var r SARIFResult
	require.NoError(t, json.Unmarshal([]byte(input), &r))

	assert.Nil(t, r.Extras)

	out, err := json.Marshal(r)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	// properties should not appear when empty.
	assert.NotContains(t, result, "properties")

	assert.Contains(t, result, "ruleId")
	assert.Contains(t, result, "level")
	assert.Contains(t, result, "message")
}
