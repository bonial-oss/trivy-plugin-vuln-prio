// SPDX-FileCopyrightText: 2025 Anchore, Inc.
// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

func TestRiskScore_KEV_Ransomware(t *testing.T) {
	// CVE in KEV with ransomware=Known, CRITICAL severity, no CVSS.
	// threat=1.0, severity=0.9, kevMod=1.1 -> min(1.0 * 0.9 * 1.1, 1.0) * 100 = 99.0
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2021-44228",
		KnownRansomwareCampaignUse: "Known",
	}
	got := RiskScore(nil, kev, "CRITICAL", nil)
	assert.InEpsilon(t, 99.0, got, 0.01)
}

func TestRiskScore_KEV_NoRansomware(t *testing.T) {
	// CVE in KEV, ransomware=Unknown, HIGH severity, no CVSS.
	// threat=1.0, severity=0.75, kevMod=1.05 -> min(1.0 * 0.75 * 1.05, 1.0) * 100 = 78.75
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2023-12345",
		KnownRansomwareCampaignUse: "Unknown",
	}
	got := RiskScore(nil, kev, "HIGH", nil)
	assert.InEpsilon(t, 78.75, got, 0.01)
}

func TestRiskScore_EPSSOnly(t *testing.T) {
	// EPSS=0.42, HIGH severity, not in KEV, no CVSS.
	// threat=0.42, severity=0.75, kevMod=1.0 -> 0.42 * 0.75 * 1.0 * 100 = 31.5
	epss := &types.EPSSEntry{
		CVE:   "CVE-2024-99999",
		Score: 0.42,
	}
	got := RiskScore(epss, nil, "HIGH", nil)
	assert.InEpsilon(t, 31.5, got, 0.01)
}

func TestRiskScore_NoData(t *testing.T) {
	// No EPSS, not in KEV -> 0.0
	got := RiskScore(nil, nil, "HIGH", nil)
	assert.InDelta(t, 0.0, got, 0.01)
}

func TestRiskScore_Capped(t *testing.T) {
	// High values that would exceed 1.0 before scaling -> capped at 100.0
	// KEV with ransomware=Known: threat=1.0, kevMod=1.1
	// CRITICAL severity: 0.9
	// With high CVSS that pushes severity above 0.9:
	// e.g. CVSS V3Score = 10.0 -> avgBase=1.0 -> severity=(0.9+1.0)/2=0.95
	// result: min(1.0 * 0.95 * 1.1, 1.0) * 100 = min(1.045, 1.0) * 100 = 100.0
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2021-44228",
		KnownRansomwareCampaignUse: "Known",
	}
	cvss := json.RawMessage(`{"nvd": {"V3Score": 10.0}}`)
	got := RiskScore(nil, kev, "CRITICAL", cvss)
	assert.InEpsilon(t, 100.0, got, 0.01)
}

func TestSeverityToScore(t *testing.T) {
	tests := []struct {
		severity string
		want     float64
	}{
		{"negligible", 0.5},
		{"NEGLIGIBLE", 0.5},
		{"low", 3.0},
		{"LOW", 3.0},
		{"medium", 5.0},
		{"MEDIUM", 5.0},
		{"high", 7.5},
		{"HIGH", 7.5},
		{"critical", 9.0},
		{"CRITICAL", 9.0},
		{"unknown", 5.0},
		{"", 5.0},
		{"something-else", 5.0},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := severityToScore(tt.severity)
			assert.InEpsilon(t, tt.want, got, 0.01)
		})
	}
}

func TestAverageCVSSBaseScore(t *testing.T) {
	tests := []struct {
		name string
		raw  json.RawMessage
		want float64
	}{
		{
			name: "V3Score only",
			raw:  json.RawMessage(`{"nvd": {"V3Score": 9.8}}`),
			want: 9.8,
		},
		{
			name: "V2Score only",
			raw:  json.RawMessage(`{"nvd": {"V2Score": 7.5}}`),
			want: 7.5,
		},
		{
			name: "mixed V3 and V2 across providers",
			// nvd has V3Score=9.8, redhat has V2Score=7.5
			// average = (9.8 + 7.5) / 2 = 8.65
			raw:  json.RawMessage(`{"nvd": {"V3Score": 9.8}, "redhat": {"V2Score": 7.5}}`),
			want: 8.65,
		},
		{
			name: "V3Score preferred over V2Score in same entry",
			// When both are present, V3Score takes precedence
			raw:  json.RawMessage(`{"nvd": {"V3Score": 9.8, "V2Score": 7.5}}`),
			want: 9.8,
		},
		{
			name: "V40Score only",
			raw:  json.RawMessage(`{"nvd": {"V40Score": 8.5}}`),
			want: 8.5,
		},
		{
			name: "V40Score preferred over V3Score and V2Score",
			raw:  json.RawMessage(`{"nvd": {"V40Score": 8.5, "V3Score": 9.8, "V2Score": 7.5}}`),
			want: 8.5,
		},
		{
			name: "mixed V40 and V3 across providers",
			// nvd has V40Score=8.5, redhat has V3Score=8.0 -> average=(8.5+8.0)/2=8.25
			raw:  json.RawMessage(`{"nvd": {"V40Score": 8.5}, "redhat": {"V3Score": 8.0}}`),
			want: 8.25,
		},
		{
			name: "multiple V3Scores",
			// nvd V3Score=9.8, redhat V3Score=8.0 -> average=(9.8+8.0)/2=8.9
			raw:  json.RawMessage(`{"nvd": {"V3Score": 9.8}, "redhat": {"V3Score": 8.0}}`),
			want: 8.9,
		},
		{
			name: "empty JSON object",
			raw:  json.RawMessage(`{}`),
			want: 0,
		},
		{
			name: "nil input",
			raw:  nil,
			want: 0,
		},
		{
			name: "empty slice",
			raw:  json.RawMessage(``),
			want: 0,
		},
		{
			name: "invalid JSON",
			raw:  json.RawMessage(`not json`),
			want: 0,
		},
		{
			name: "entry with no scores",
			raw:  json.RawMessage(`{"nvd": {}}`),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := averageCVSSBaseScore(tt.raw)
			if tt.want == 0 {
				assert.Zero(t, got)
			} else {
				assert.InEpsilon(t, tt.want, got, 0.01)
			}
		})
	}
}

func TestRiskScore_WithCVSS(t *testing.T) {
	// Test that CVSS score is factored into severity calculation.
	// CRITICAL severity (9.0) with CVSS V3Score 7.0
	// severity = (0.9 + 0.7) / 2 = 0.8
	// KEV with ransomware=Known: threat=1.0, kevMod=1.1
	// result: min(1.0 * 0.8 * 1.1, 1.0) * 100 = 88.0
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2021-44228",
		KnownRansomwareCampaignUse: "Known",
	}
	cvss := json.RawMessage(`{"nvd": {"V3Score": 7.0}}`)
	got := RiskScore(nil, kev, "CRITICAL", cvss)
	assert.InEpsilon(t, 88.0, got, 0.01)
}

func TestRiskScoreWithCVSSBase(t *testing.T) {
	// Same scenario as TestRiskScore_WithCVSS but using direct base score.
	// CRITICAL severity (9.0) with CVSSBaseScore 7.0
	// severity = (0.9 + 0.7) / 2 = 0.8
	// KEV with ransomware=Known: threat=1.0, kevMod=1.1
	// result: min(1.0 * 0.8 * 1.1, 1.0) * 100 = 88.0
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2021-44228",
		KnownRansomwareCampaignUse: "Known",
	}
	got := RiskScoreWithCVSSBase(nil, kev, "CRITICAL", 7.0)
	assert.InEpsilon(t, 88.0, got, 0.01)
}

func TestRiskScoreWithCVSSBase_ZeroFallsBackToSeverity(t *testing.T) {
	// When CVSSBaseScore is 0, should behave like RiskScore with nil CVSS.
	// HIGH severity (7.5), no CVSS
	// KEV with no ransomware: threat=1.0, severity=0.75, kevMod=1.05
	// result: min(1.0 * 0.75 * 1.05, 1.0) * 100 = 78.75
	kev := &types.KEVEntry{
		CVEID:                      "CVE-2023-12345",
		KnownRansomwareCampaignUse: "Unknown",
	}
	got := RiskScoreWithCVSSBase(nil, kev, "HIGH", 0)
	assert.InEpsilon(t, 78.75, got, 0.01)

	// Should match RiskScore with nil CVSS
	gotOriginal := RiskScore(nil, kev, "HIGH", nil)
	assert.InEpsilon(t, gotOriginal, got, 0.01)
}
