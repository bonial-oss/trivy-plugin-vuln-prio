// SPDX-FileCopyrightText: 2025 Anchore, Inc.
// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

// Risk score calculation based on the formula from Grype
// (https://github.com/anchore/grype), licensed under Apache-2.0.

package enricher

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// RiskScore computes a composite risk score (0.0–100.0) from EPSS, KEV, and severity.
func RiskScore(epss *types.EPSSEntry, kev *types.KEVEntry, severity string, cvssRaw json.RawMessage) float64 {
	t := threat(epss, kev)
	s := severityScore(severity, cvssRaw)
	k := kevModifier(kev)
	return math.Min(t*s*k, 1.0) * 100.0
}

func threat(epss *types.EPSSEntry, kev *types.KEVEntry) float64 {
	if kev != nil {
		return 1.0
	}
	if epss != nil {
		return epss.Score
	}
	return 0.0
}

func kevModifier(kev *types.KEVEntry) float64 {
	if kev == nil {
		return 1.0
	}
	if strings.EqualFold(kev.KnownRansomwareCampaignUse, "known") {
		return 1.1
	}
	return 1.05
}

// RiskScoreWithCVSSBase computes a composite risk score using a pre-computed
// CVSS base score instead of raw Trivy JSON. Used by the SARIF enricher where
// CVSS data comes as flat floats from rule properties.
func RiskScoreWithCVSSBase(epss *types.EPSSEntry, kev *types.KEVEntry, severity string, cvssBaseScore float64) float64 {
	t := threat(epss, kev)
	s := severityScoreWithBase(severity, cvssBaseScore)
	k := kevModifier(kev)
	return math.Min(t*s*k, 1.0) * 100.0
}

func severityScore(severity string, cvssRaw json.RawMessage) float64 {
	return severityScoreWithBase(severity, averageCVSSBaseScore(cvssRaw))
}

func severityScoreWithBase(severity string, cvssBaseScore float64) float64 {
	strScore := severityToScore(severity) / 10.0
	avgBase := cvssBaseScore / 10.0
	if avgBase == 0 {
		return strScore
	}
	return (strScore + avgBase) / 2.0
}

func severityToScore(severity string) float64 {
	switch strings.ToLower(severity) {
	case "negligible":
		return 0.5
	case "low":
		return 3.0
	case "medium":
		return 5.0
	case "high":
		return 7.5
	case "critical":
		return 9.0
	default:
		return 5.0
	}
}

// averageCVSSBaseScore extracts base scores from Trivy's CVSS JSON.
// Trivy CVSS format: {"nvd": {"V3Score": 9.8, "V40Score": 8.2}, "redhat": {"V3Score": 8.1}}
// For each vendor entry, the highest-version score is preferred: V4.0 > V3 > V2.
func averageCVSSBaseScore(cvssRaw json.RawMessage) float64 {
	if len(cvssRaw) == 0 {
		return 0
	}
	var cvssMap map[string]struct {
		V2Score  *float64 `json:"V2Score"`
		V3Score  *float64 `json:"V3Score"`
		V40Score *float64 `json:"V40Score"`
	}
	if err := json.Unmarshal(cvssRaw, &cvssMap); err != nil {
		return 0
	}
	var sum float64
	var count int
	for _, entry := range cvssMap {
		switch {
		case entry.V40Score != nil:
			sum += *entry.V40Score
			count++
		case entry.V3Score != nil:
			sum += *entry.V3Score
			count++
		case entry.V2Score != nil:
			sum += *entry.V2Score
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}
