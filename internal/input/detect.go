// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package input

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

type Format int

const (
	FormatJSON Format = iota
	FormatSARIF
)

type ParseResult struct {
	Format      Format
	TrivyReport *types.Report
	SARIFReport *types.SARIFReport
}

func Parse(data []byte) (*ParseResult, error) {
	// Probe the JSON to detect format
	var probe struct {
		Schema        string          `json:"$schema"`
		Version       string          `json:"version"`
		Runs          json.RawMessage `json:"runs"`
		SchemaVersion *int            `json:"SchemaVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("invalid JSON input: %w", err)
	}

	// SARIF: has runs array and (version 2.1.0 or $schema containing "sarif")
	if probe.Runs != nil && (probe.Version == "2.1.0" || strings.Contains(probe.Schema, "sarif")) {
		var report types.SARIFReport
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("parsing SARIF: %w", err)
		}
		return &ParseResult{Format: FormatSARIF, SARIFReport: &report}, nil
	}

	// Trivy JSON: has SchemaVersion
	if probe.SchemaVersion != nil {
		var report types.Report
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, fmt.Errorf("parsing Trivy JSON: %w", err)
		}
		return &ParseResult{Format: FormatJSON, TrivyReport: &report}, nil
	}

	return nil, fmt.Errorf("unrecognized input format: not Trivy JSON or SARIF")
}
