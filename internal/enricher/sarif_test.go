// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// makeSARIFReportWithTool builds a SARIF report using custom tool JSON.
func makeSARIFReportWithTool(toolJSON json.RawMessage, results ...types.SARIFResult) *types.SARIFReport {
	return &types.SARIFReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []types.SARIFRun{
			{
				Tool:    toolJSON,
				Results: results,
			},
		},
	}
}

// makeSARIFReport builds a SARIF report with a minimal tool (no rules).
// Use this for tests that exercise the level-based fallback path.
func makeSARIFReport(results ...types.SARIFResult) *types.SARIFReport {
	return makeSARIFReportWithTool(
		json.RawMessage(`{"driver":{"name":"Trivy","version":"0.50.0"}}`),
		results...,
	)
}

// toolJSONWithRules builds tool JSON including rules with severity tags and
// optional CVSS base scores. Used by tests that exercise the rule-based path.
func toolJSONWithRules() json.RawMessage {
	return json.RawMessage(`{
		"driver": {
			"name": "Trivy",
			"version": "0.50.0",
			"rules": [
				{
					"id": "CVE-2024-1234",
					"properties": {
						"tags": ["vulnerability", "security", "CRITICAL"],
						"cvssv3_baseScore": 9.8,
						"security-severity": "9.8"
					}
				},
				{
					"id": "CVE-2023-5678",
					"properties": {
						"tags": ["vulnerability", "security", "MEDIUM"],
						"cvssv3_baseScore": 5.5,
						"security-severity": "5.5"
					}
				}
			]
		}
	}`)
}

func TestEnrichSARIF(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeSARIFReportWithTool(
		toolJSONWithRules(),
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Critical vulnerability"}`),
		},
		types.SARIFResult{
			RuleID:  "CVE-2023-5678",
			Level:   "warning",
			Message: json.RawMessage(`{"text":"Medium vulnerability"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{})
	require.NoError(t, err)

	results := result.Report.Runs[0].Results
	require.Len(t, results, 2)

	// Verify CVE-2024-1234 (in both EPSS and KEV).
	r0 := results[0]
	require.NotNil(t, r0.Properties, "CVE-2024-1234: Properties is nil")
	vpRaw0, ok := r0.Properties["vulnPrio"]
	require.True(t, ok, "CVE-2024-1234: vulnPrio missing from Properties")

	var vp0 types.VulnPrio
	require.NoError(t, json.Unmarshal(vpRaw0, &vp0), "CVE-2024-1234: unmarshal VulnPrio")
	require.NotNil(t, vp0.EPSS, "CVE-2024-1234: EPSS is nil")
	require.NotNil(t, vp0.EPSS.Score, "CVE-2024-1234: EPSS.Score is nil")
	assert.InEpsilon(t, 0.97, *vp0.EPSS.Score, 0.01, "CVE-2024-1234: EPSS.Score")
	require.NotNil(t, vp0.KEV, "CVE-2024-1234: KEV is nil")
	assert.True(t, vp0.KEV.Listed, "CVE-2024-1234: KEV.Listed = false, want true")
	require.NotNil(t, vp0.Risk, "CVE-2024-1234: Risk is nil")
	assert.Greater(t, *vp0.Risk, 0.0, "CVE-2024-1234: Risk should be > 0")

	// Verify CVE-2023-5678 (in EPSS only, not in KEV).
	r1 := results[1]
	require.NotNil(t, r1.Properties, "CVE-2023-5678: Properties is nil")
	vpRaw1, ok := r1.Properties["vulnPrio"]
	require.True(t, ok, "CVE-2023-5678: vulnPrio missing from Properties")

	var vp1 types.VulnPrio
	require.NoError(t, json.Unmarshal(vpRaw1, &vp1), "CVE-2023-5678: unmarshal VulnPrio")
	require.NotNil(t, vp1.EPSS, "CVE-2023-5678: EPSS is nil")
	require.NotNil(t, vp1.EPSS.Score, "CVE-2023-5678: EPSS.Score is nil")
	assert.InEpsilon(t, 0.42, *vp1.EPSS.Score, 0.01, "CVE-2023-5678: EPSS.Score")
	require.NotNil(t, vp1.KEV, "CVE-2023-5678: KEV is nil")
	assert.False(t, vp1.KEV.Listed, "CVE-2023-5678: KEV.Listed = true, want false")
	require.NotNil(t, vp1.Risk, "CVE-2023-5678: Risk is nil")
}

func TestEnrichSARIF_CriticalSeverityFromRules(t *testing.T) {
	// Verifies that CRITICAL severity (from rule tags) produces a higher
	// risk score than the level-based fallback which maps error -> HIGH.
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// With rules: severity=CRITICAL, cvssv3_baseScore=9.8
	reportWithRules := makeSARIFReportWithTool(
		toolJSONWithRules(),
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Critical vulnerability"}`),
		},
	)

	// Without rules: falls back to level "error" -> HIGH
	reportNoRules := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Critical vulnerability"}`),
		},
	)

	resultWithRules, err := enricher.EnrichSARIF(reportWithRules, Config{})
	require.NoError(t, err, "EnrichSARIF() with rules")
	resultNoRules, err := enricher.EnrichSARIF(reportNoRules, Config{})
	require.NoError(t, err, "EnrichSARIF() without rules")

	var vpWithRules, vpNoRules types.VulnPrio
	require.NoError(t, json.Unmarshal(resultWithRules.Report.Runs[0].Results[0].Properties["vulnPrio"], &vpWithRules))
	require.NoError(t, json.Unmarshal(resultNoRules.Report.Runs[0].Results[0].Properties["vulnPrio"], &vpNoRules))

	require.NotNil(t, vpWithRules.Risk, "Risk should not be nil (with rules)")
	require.NotNil(t, vpNoRules.Risk, "Risk should not be nil (without rules)")

	// CRITICAL+CVSS9.8 should yield a higher risk than HIGH+noCVSS.
	assert.Greater(t, *vpWithRules.Risk, *vpNoRules.Risk, "Rule-based risk should be > fallback risk")
}

func TestEnrichSARIF_FallsBackToLevelWhenNoRules(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// Tool JSON without rules -- should fall back to level mapping.
	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"test"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{})
	require.NoError(t, err)

	var vp types.VulnPrio
	require.NoError(t, json.Unmarshal(result.Report.Runs[0].Results[0].Properties["vulnPrio"], &vp))
	require.NotNil(t, vp.Risk, "Risk should not be nil")

	// Verify we get the same score as level-based: error -> HIGH, no CVSS
	// KEV with Known ransomware: threat=1.0, severity=0.75, kevMod=1.1
	// -> min(1.0 * 0.75 * 1.1, 1.0) * 100 = 82.5
	assert.InEpsilon(t, 82.5, *vp.Risk, 0.01, "Risk (level fallback: error -> HIGH)")
}

func TestEnrichSARIF_PreservesExistingProperties(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Critical vulnerability"}`),
			Properties: map[string]json.RawMessage{
				"existingProp": json.RawMessage(`"should survive"`),
				"anotherProp":  json.RawMessage(`42`),
			},
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{})
	require.NoError(t, err)

	props := result.Report.Runs[0].Results[0].Properties

	// vulnPrio should be set.
	assert.Contains(t, props, "vulnPrio", "vulnPrio missing from Properties")

	// Existing properties should survive.
	assert.Contains(t, props, "existingProp", "existingProp missing from Properties after enrichment")
	assert.Contains(t, props, "anotherProp", "anotherProp missing from Properties after enrichment")

	// Verify existing property values.
	var existingVal string
	require.NoError(t, json.Unmarshal(props["existingProp"], &existingVal), "unmarshal existingProp")
	assert.Equal(t, "should survive", existingVal)
}

func TestEnrichSARIF_PolicyViolation(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// CVE-2024-1234 is in KEV -> policy violation when FailOnKEV=true.
	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"KEV vulnerability"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{FailOnKEV: true})
	require.NoError(t, err)

	assert.True(t, result.PolicyViolation, "expected PolicyViolation=true when FailOnKEV=true and KEV vuln present")
}

func TestEnrichSARIF_PolicyViolation_EPSS(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// CVE-2024-1234 has EPSS=0.97, which is >= 0.5.
	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"High EPSS vulnerability"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{FailOnEPSSThreshold: 0.5})
	require.NoError(t, err)

	assert.True(t, result.PolicyViolation, "expected PolicyViolation=true when FailOnEPSSThreshold=0.5 and EPSS >= 0.5")
}

func TestEnrichSARIF_NoPolicyViolation(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// CVE-2023-9999 is in neither EPSS nor KEV (score=nil).
	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2023-9999",
			Level:   "note",
			Message: json.RawMessage(`{"text":"Unknown vulnerability"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{FailOnKEV: true, FailOnEPSSThreshold: 0.5})
	require.NoError(t, err)

	assert.False(t, result.PolicyViolation, "expected PolicyViolation=false when no KEV and no EPSS scores above threshold")
}

func TestEnrichSARIF_NoEPSS(t *testing.T) {
	kevSource := setupKEVSource(t)
	// Simulate NoEPSS by passing nil for epssSource.
	enricher := New(nil, kevSource)

	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Test"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{})
	require.NoError(t, err)

	props := result.Report.Runs[0].Results[0].Properties
	vpRaw, ok := props["vulnPrio"]
	require.True(t, ok, "vulnPrio missing from Properties")

	var vp types.VulnPrio
	require.NoError(t, json.Unmarshal(vpRaw, &vp), "unmarshal VulnPrio")

	assert.Nil(t, vp.EPSS, "EPSS should be nil when NoEPSS=true")
	require.NotNil(t, vp.KEV, "KEV should be present when NoEPSS=true")
	assert.True(t, vp.KEV.Listed, "KEV.Listed should be true for CVE-2024-1234")
	assert.Nil(t, vp.Risk, "Risk should be nil when EPSS is disabled")
}

func TestEnrichSARIF_NoKEV(t *testing.T) {
	epssSource := setupEPSSSource(t)
	// Simulate NoKEV by passing nil for kevSource.
	enricher := New(epssSource, nil)

	report := makeSARIFReport(
		types.SARIFResult{
			RuleID:  "CVE-2024-1234",
			Level:   "error",
			Message: json.RawMessage(`{"text":"Test"}`),
		},
	)

	result, err := enricher.EnrichSARIF(report, Config{})
	require.NoError(t, err)

	props := result.Report.Runs[0].Results[0].Properties
	vpRaw, ok := props["vulnPrio"]
	require.True(t, ok, "vulnPrio missing from Properties")

	var vp types.VulnPrio
	require.NoError(t, json.Unmarshal(vpRaw, &vp), "unmarshal VulnPrio")

	assert.Nil(t, vp.KEV, "KEV should be nil when NoKEV=true")
	require.NotNil(t, vp.EPSS, "EPSS should be present when NoKEV=true")
	require.NotNil(t, vp.EPSS.Score, "EPSS.Score should not be nil for CVE-2024-1234")
	assert.Nil(t, vp.Risk, "Risk should be nil when KEV is disabled")
}

func TestSarifLevelToSeverity(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{"error", "HIGH"},
		{"ERROR", "HIGH"},
		{"warning", "MEDIUM"},
		{"WARNING", "MEDIUM"},
		{"note", "LOW"},
		{"NOTE", "LOW"},
		{"", "MEDIUM"},
		{"unknown", "MEDIUM"},
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			got := sarifLevelToSeverity(tt.level)
			assert.Equal(t, tt.want, got, "sarifLevelToSeverity(%q)", tt.level)
		})
	}
}

func TestSeverityFromRuleProperties(t *testing.T) {
	tests := []struct {
		name  string
		props map[string]json.RawMessage
		want  string
	}{
		{
			name: "severity in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "security", "HIGH"]`),
			},
			want: "HIGH",
		},
		{
			name: "CRITICAL in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "security", "CRITICAL"]`),
			},
			want: "CRITICAL",
		},
		{
			name: "lowercase severity in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "security", "medium"]`),
			},
			want: "MEDIUM",
		},
		{
			name: "severity not at end of tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["LOW", "vulnerability", "security"]`),
			},
			want: "LOW",
		},
		{
			name: "no severity in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "security"]`),
			},
			want: "",
		},
		{
			name:  "no tags key",
			props: map[string]json.RawMessage{},
			want:  "",
		},
		{
			name:  "nil props",
			props: nil,
			want:  "",
		},
		{
			name: "invalid tags JSON",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`not json`),
			},
			want: "",
		},
		{
			name: "NEGLIGIBLE in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "security", "NEGLIGIBLE"]`),
			},
			want: "NEGLIGIBLE",
		},
		{
			name: "UNKNOWN in tags",
			props: map[string]json.RawMessage{
				"tags": json.RawMessage(`["vulnerability", "UNKNOWN", "security"]`),
			},
			want: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := severityFromRuleProperties(tt.props)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCVSSBaseScoreFromRuleProperties(t *testing.T) {
	tests := []struct {
		name  string
		props map[string]json.RawMessage
		want  float64
	}{
		{
			name: "v3 only",
			props: map[string]json.RawMessage{
				"cvssv3_baseScore": json.RawMessage(`7.5`),
			},
			want: 7.5,
		},
		{
			name: "v4.0 only",
			props: map[string]json.RawMessage{
				"cvssv40_baseScore": json.RawMessage(`8.7`),
			},
			want: 8.7,
		},
		{
			name: "both v3 and v4.0 averaged",
			props: map[string]json.RawMessage{
				"cvssv3_baseScore":  json.RawMessage(`7.0`),
				"cvssv40_baseScore": json.RawMessage(`9.0`),
			},
			want: 8.0,
		},
		{
			name:  "no CVSS keys",
			props: map[string]json.RawMessage{},
			want:  0,
		},
		{
			name:  "nil props",
			props: nil,
			want:  0,
		},
		{
			name: "zero score ignored",
			props: map[string]json.RawMessage{
				"cvssv3_baseScore":  json.RawMessage(`0`),
				"cvssv40_baseScore": json.RawMessage(`8.0`),
			},
			want: 8.0,
		},
		{
			name: "invalid JSON ignored",
			props: map[string]json.RawMessage{
				"cvssv3_baseScore": json.RawMessage(`"not a number"`),
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cvssBaseScoreFromRuleProperties(tt.props)
			if tt.want == 0 {
				assert.Zero(t, got)
			} else {
				assert.InEpsilon(t, tt.want, got, 0.01)
			}
		})
	}
}

func TestBuildRuleIndex(t *testing.T) {
	t.Run("parses rules from tool JSON", func(t *testing.T) {
		toolJSON := json.RawMessage(`{
			"driver": {
				"name": "Trivy",
				"rules": [
					{
						"id": "CVE-2024-0001",
						"properties": {
							"tags": ["vulnerability", "security", "CRITICAL"],
							"cvssv3_baseScore": 9.8
						}
					},
					{
						"id": "CVE-2024-0002",
						"properties": {
							"tags": ["vulnerability", "security", "LOW"]
						}
					}
				]
			}
		}`)

		index := buildRuleIndex(toolJSON)
		require.NotNil(t, index, "expected non-nil index")
		require.Len(t, index, 2)

		r1 := index["CVE-2024-0001"]
		assert.Equal(t, "CRITICAL", r1.Severity, "CVE-2024-0001 severity")
		assert.InEpsilon(t, 9.8, r1.CVSSBaseScore, 0.01, "CVE-2024-0001 CVSSBaseScore")

		r2 := index["CVE-2024-0002"]
		assert.Equal(t, "LOW", r2.Severity, "CVE-2024-0002 severity")
		assert.Zero(t, r2.CVSSBaseScore, "CVE-2024-0002 CVSSBaseScore")
	})

	t.Run("returns nil for empty tool", func(t *testing.T) {
		index := buildRuleIndex(nil)
		assert.Nil(t, index, "expected nil index for nil tool")
	})

	t.Run("returns nil for tool without rules", func(t *testing.T) {
		index := buildRuleIndex(json.RawMessage(`{"driver":{"name":"Trivy"}}`))
		assert.Nil(t, index, "expected nil index for tool without rules")
	})

	t.Run("returns nil for invalid JSON", func(t *testing.T) {
		index := buildRuleIndex(json.RawMessage(`not json`))
		assert.Nil(t, index, "expected nil index for invalid JSON")
	})
}

func TestResolveRuleData(t *testing.T) {
	index := map[string]sarifRuleData{
		"CVE-2024-0001": {Severity: "CRITICAL", CVSSBaseScore: 9.8},
		"CVE-2024-0002": {Severity: "LOW", CVSSBaseScore: 0},
	}

	t.Run("returns rule data when found", func(t *testing.T) {
		sev, cvss := resolveRuleData(index, "CVE-2024-0001", "error")
		assert.Equal(t, "CRITICAL", sev)
		assert.InEpsilon(t, 9.8, cvss, 0.01)
	})

	t.Run("falls back to level when rule not found", func(t *testing.T) {
		sev, cvss := resolveRuleData(index, "CVE-UNKNOWN", "warning")
		assert.Equal(t, "MEDIUM", sev)
		assert.Zero(t, cvss)
	})

	t.Run("falls back to level when index is nil", func(t *testing.T) {
		sev, cvss := resolveRuleData(nil, "CVE-2024-0001", "note")
		assert.Equal(t, "LOW", sev)
		assert.Zero(t, cvss)
	})
}
