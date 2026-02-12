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
	epssEnabled := e.epss != nil
	kevEnabled := e.kev != nil

	policyViolation := false

	for i := range report.Runs {
		run := &report.Runs[i]

		// Build rule index from tool.driver.rules for severity/CVSS lookup.
		ruleIndex := buildRuleIndex(run.Tool)

		for j := range run.Results {
			result := &run.Results[j]

			// Step 1: Extract CVE ID from ruleId.
			cveID := result.RuleID

			var epssData *types.EPSSData
			var kevData *types.KEVData
			var epssEntry *types.EPSSEntry
			var kevEntry *types.KEVEntry

			// Step 2: EPSS lookup.
			if epssEnabled {
				epssEntry = e.epss.Lookup(cveID)
				if epssEntry != nil {
					score := epssEntry.Score
					percentile := epssEntry.Percentile
					epssData = &types.EPSSData{
						Score:        &score,
						Percentile:   &percentile,
						ModelVersion: e.epss.ModelVersion(),
						ScoreDate:    e.epss.ScoreDate(),
					}
				} else {
					epssData = &types.EPSSData{
						ModelVersion: e.epss.ModelVersion(),
						ScoreDate:    e.epss.ScoreDate(),
					}
				}
			}

			// Step 3: KEV lookup.
			if kevEnabled {
				kevEntry = e.kev.Lookup(cveID)
				if kevEntry != nil {
					kevData = &types.KEVData{
						Listed:                     true,
						DateAdded:                  kevEntry.DateAdded,
						DueDate:                    kevEntry.DueDate,
						KnownRansomwareCampaignUse: kevEntry.KnownRansomwareCampaignUse,
						VendorProject:              kevEntry.VendorProject,
						Product:                    kevEntry.Product,
					}
				} else {
					kevData = &types.KEVData{
						Listed: false,
					}
				}
			}

			// Step 4: Compute risk score when both sources are enabled.
			// Extract severity and CVSS from rule; fall back to level mapping.
			var risk *float64
			if epssEnabled && kevEnabled {
				severity, cvssBase := resolveRuleData(ruleIndex, cveID, result.Level)
				r := RiskScoreWithCVSSBase(epssEntry, kevEntry, severity, cvssBase)
				risk = &r
			}

			// Step 5: Build VulnPrio.
			vulnPrio := &types.VulnPrio{}
			if risk != nil {
				vulnPrio.Risk = risk
			}
			if epssData != nil {
				vulnPrio.EPSS = epssData
			}
			if kevData != nil {
				vulnPrio.KEV = kevData
			}

			// Step 6: Marshal VulnPrio to json.RawMessage.
			vpJSON, err := json.Marshal(vulnPrio)
			if err != nil {
				return nil, fmt.Errorf("marshaling VulnPrio for %s: %w", cveID, err)
			}

			// Step 7: Initialize properties map if nil and set vulnPrio.
			if result.Properties == nil {
				result.Properties = make(map[string]json.RawMessage)
			}
			result.Properties["vulnPrio"] = json.RawMessage(vpJSON)

			// Step 8: Check policy violations.
			if cfg.FailOnKEV && kevData != nil && kevData.Listed {
				policyViolation = true
			}
			if cfg.FailOnEPSSThreshold > 0 && epssData != nil &&
				epssData.Score != nil && *epssData.Score >= cfg.FailOnEPSSThreshold {
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
// a map from rule ID to extracted severity/CVSS data.
func buildRuleIndex(toolRaw json.RawMessage) map[string]sarifRuleData {
	if len(toolRaw) == 0 {
		return nil
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
		return nil
	}

	if len(tool.Driver.Rules) == 0 {
		return nil
	}

	index := make(map[string]sarifRuleData, len(tool.Driver.Rules))
	for _, rule := range tool.Driver.Rules {
		data := sarifRuleData{
			Severity:      severityFromRuleProperties(rule.Properties),
			CVSSBaseScore: cvssBaseScoreFromRuleProperties(rule.Properties),
		}
		index[rule.ID] = data
	}
	return index
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
