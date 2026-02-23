// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// SARIFResult holds the enriched SARIF report and policy violation status.
type SARIFResult struct {
	Report          *types.SARIFReport
	PolicyViolation bool
}

// EnrichSARIF processes a SARIF report, adding VulnPrio data to each result's
// properties and checking policy violations.
func (e *Enricher) EnrichSARIF(report *types.SARIFReport, cfg Config) (*SARIFResult, error) {
	policyViolation := false

	for i := range report.Runs {
		run := &report.Runs[i]

		// Build rule index from tool.driver.rules for severity/CVSS lookup.
		ruleIndex, ruleIDsByIndex := buildRuleIndex(run.Tool)

		for j := range run.Results {
			result := &run.Results[j]

			// Extract CVE ID from ruleId, falling back to ruleIndex.
			cveID := result.RuleID
			if cveID == "" && result.RuleIndex != nil {
				if idx := *result.RuleIndex; idx >= 0 && idx < len(ruleIDsByIndex) {
					cveID = ruleIDsByIndex[idx]
				}
			}

			// Resolve severity and CVSS from rule data; fall back to level mapping.
			severity, cvssBase := resolveRuleData(ruleIndex, cveID, result.Level)

			// Build VulnPrio using the shared helper.
			vulnPrio := e.buildVulnPrio(cveID, severity, cvssBase)

			// Marshal VulnPrio to json.RawMessage.
			vpJSON, err := json.Marshal(vulnPrio)
			if err != nil {
				return nil, fmt.Errorf("marshaling VulnPrio for %s: %w", cveID, err)
			}

			// Initialize properties map if nil and set vulnPrio.
			if result.Properties == nil {
				result.Properties = make(map[string]json.RawMessage)
			}
			result.Properties["vulnPrio"] = json.RawMessage(vpJSON)

			// Check policy violations.
			if cfg.FailOnKEV && vulnPrio.KEV != nil && vulnPrio.KEV.Listed {
				policyViolation = true
			}
			if cfg.FailOnEPSSThreshold > 0 && vulnPrio.EPSS != nil &&
				vulnPrio.EPSS.Score != nil && *vulnPrio.EPSS.Score >= cfg.FailOnEPSSThreshold {
				policyViolation = true
			}
		}
	}

	return &SARIFResult{
		Report:          report,
		PolicyViolation: policyViolation,
	}, nil
}

// sarifRuleData holds severity and CVSS data extracted from a SARIF rule.
type sarifRuleData struct {
	Severity      string
	CVSSBaseScore float64
}

// buildRuleIndex parses tool.driver.rules from the SARIF tool JSON and builds
// a map from rule ID to extracted severity/CVSS data, plus a positional slice
// mapping array index to rule ID (for ruleIndex-based lookup).
func buildRuleIndex(toolRaw json.RawMessage) (map[string]sarifRuleData, []string) {
	if len(toolRaw) == 0 {
		return nil, nil
	}

	var tool struct {
		Driver struct {
			Rules []struct {
				ID         string                     `json:"id"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"rules"`
		} `json:"driver"`
	}
	if err := json.Unmarshal(toolRaw, &tool); err != nil {
		return nil, nil
	}

	if len(tool.Driver.Rules) == 0 {
		return nil, nil
	}

	index := make(map[string]sarifRuleData, len(tool.Driver.Rules))
	ruleIDs := make([]string, len(tool.Driver.Rules))
	for i, rule := range tool.Driver.Rules {
		data := sarifRuleData{
			Severity:      severityFromRuleProperties(rule.Properties),
			CVSSBaseScore: cvssBaseScoreFromRuleProperties(rule.Properties),
		}
		index[rule.ID] = data
		ruleIDs[i] = rule.ID
	}
	return index, ruleIDs
}

// resolveRuleData looks up the rule for a result and returns the severity
// string and CVSS base score. Falls back to sarifLevelToSeverity if the
// rule is not found or lacks severity data.
func resolveRuleData(ruleIndex map[string]sarifRuleData, ruleID, level string) (string, float64) {
	if ruleIndex != nil {
		if data, ok := ruleIndex[ruleID]; ok && data.Severity != "" {
			return data.Severity, data.CVSSBaseScore
		}
	}
	return sarifLevelToSeverity(level), 0
}

// knownSeverities maps recognized Trivy severity strings to true for lookup.
var knownSeverities = map[string]bool{
	"CRITICAL":   true,
	"HIGH":       true,
	"MEDIUM":     true,
	"LOW":        true,
	"NEGLIGIBLE": true,
	"UNKNOWN":    true,
}

// severityFromRuleProperties scans the tags array in rule properties for a
// recognized Trivy severity string (CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE,
// UNKNOWN). Returns empty string if none found.
func severityFromRuleProperties(props map[string]json.RawMessage) string {
	raw, ok := props["tags"]
	if !ok {
		return ""
	}
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil {
		return ""
	}
	for _, tag := range tags {
		upper := strings.ToUpper(tag)
		if knownSeverities[upper] {
			return upper
		}
	}
	return ""
}

// cvssBaseScoreFromRuleProperties extracts CVSS base scores from rule
// properties (cvssv3_baseScore, cvssv40_baseScore) and returns their average.
// Returns 0 if no scores are found.
func cvssBaseScoreFromRuleProperties(props map[string]json.RawMessage) float64 {
	keys := []string{"cvssv3_baseScore", "cvssv40_baseScore"}
	var sum float64
	var count int
	for _, key := range keys {
		raw, ok := props[key]
		if !ok {
			continue
		}
		var score float64
		if err := json.Unmarshal(raw, &score); err != nil || score <= 0 {
			continue
		}
		sum += score
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

// sarifLevelToSeverity maps SARIF level values to Trivy severity strings.
func sarifLevelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
