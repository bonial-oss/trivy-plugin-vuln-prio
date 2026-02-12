// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/epss"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/kev"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// Enricher enriches Trivy report vulnerabilities with EPSS and KEV data.
type Enricher struct {
	epss *epss.Source
	kev  *kev.Source
}

// Config holds filtering and policy options for enrichment.
type Config struct {
	EPSSThreshold       float64
	KEVOnly             bool
	FailOnKEV           bool
	FailOnEPSSThreshold float64
}

// Result holds the enriched report and policy violation status.
type Result struct {
	Report          *types.Report
	PolicyViolation bool
}

// New creates a new Enricher with the given data sources.
// Either source may be nil if disabled.
func New(epssSource *epss.Source, kevSource *kev.Source) *Enricher {
	return &Enricher{
		epss: epssSource,
		kev:  kevSource,
	}
}

// Enrich processes a Trivy report, adding EPSS/KEV data to each vulnerability,
// applying filters, and checking policy violations.
func (e *Enricher) Enrich(report *types.Report, cfg Config) (*Result, error) {
	epssEnabled := e.epss != nil
	kevEnabled := e.kev != nil

	for i := range report.Results {
		res := &report.Results[i]
		for j := range res.Vulnerabilities {
			vuln := &res.Vulnerabilities[j]

			var epssData *types.EPSSData
			var kevData *types.KEVData
			var epssEntry *types.EPSSEntry
			var kevEntry *types.KEVEntry

			// Step 1: EPSS lookup.
			if epssEnabled {
				epssEntry = e.epss.Lookup(vuln.VulnerabilityID)
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
					// Entry not found: score and percentile are nil.
					epssData = &types.EPSSData{
						ModelVersion: e.epss.ModelVersion(),
						ScoreDate:    e.epss.ScoreDate(),
					}
				}
			}

			// Step 2: KEV lookup.
			if kevEnabled {
				kevEntry = e.kev.Lookup(vuln.VulnerabilityID)
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

			// Step 3: Compute risk score when both sources are enabled.
			var risk *float64
			if epssEnabled && kevEnabled {
				r := RiskScore(epssEntry, kevEntry, vuln.Severity, vuln.CVSS)
				risk = &r
			}

			// Step 4: Build VulnPrio and set on the vulnerability.
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
			vuln.VulnPrio = vulnPrio
		}

		// Step 5: Apply filters (modify the vulnerabilities slice).
		if cfg.EPSSThreshold > 0 || cfg.KEVOnly {
			filtered := make([]types.Vulnerability, 0, len(res.Vulnerabilities))
			for _, vuln := range res.Vulnerabilities {
				if cfg.EPSSThreshold > 0 {
					if vuln.VulnPrio == nil || vuln.VulnPrio.EPSS == nil ||
						vuln.VulnPrio.EPSS.Score == nil || *vuln.VulnPrio.EPSS.Score < cfg.EPSSThreshold {
						continue
					}
				}
				if cfg.KEVOnly {
					if vuln.VulnPrio == nil || vuln.VulnPrio.KEV == nil || !vuln.VulnPrio.KEV.Listed {
						continue
					}
				}
				filtered = append(filtered, vuln)
			}
			res.Vulnerabilities = filtered
		}
	}

	// Step 6: Check policy violations (don't remove, just flag).
	policyViolation := false
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			if vuln.VulnPrio == nil {
				continue
			}
			if cfg.FailOnKEV && vuln.VulnPrio.KEV != nil && vuln.VulnPrio.KEV.Listed {
				policyViolation = true
			}
			if cfg.FailOnEPSSThreshold > 0 && vuln.VulnPrio.EPSS != nil &&
				vuln.VulnPrio.EPSS.Score != nil && *vuln.VulnPrio.EPSS.Score >= cfg.FailOnEPSSThreshold {
				policyViolation = true
			}
		}
	}

	return &Result{
		Report:          report,
		PolicyViolation: policyViolation,
	}, nil
}
