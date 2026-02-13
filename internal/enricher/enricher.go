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
// applying filters, and checking policy violations. Suppressed findings
// (ExperimentalModifiedFindings) are enriched but not filtered or counted
// toward policy violations.
func (e *Enricher) Enrich(report *types.Report, cfg Config) (*Result, error) {
	for i := range report.Results {
		res := &report.Results[i]

		// Enrich regular vulnerabilities.
		for j := range res.Vulnerabilities {
			e.enrichVuln(&res.Vulnerabilities[j])
		}

		// Enrich suppressed/modified findings (enrich only, no filtering or policy).
		for j := range res.ExperimentalModifiedFindings {
			mf := &res.ExperimentalModifiedFindings[j]
			if mf.Type == "vulnerability" {
				e.enrichVuln(&mf.Finding)
			}
		}

		// Apply filters to regular vulnerabilities only.
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

	// Check policy violations against regular vulnerabilities only.
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

// enrichVuln enriches a single vulnerability with EPSS, KEV, and risk data.
func (e *Enricher) enrichVuln(vuln *types.Vulnerability) {
	vuln.VulnPrio = e.buildVulnPrio(vuln.VulnerabilityID, vuln.Severity, averageCVSSBaseScore(vuln.CVSS))
}

// buildVulnPrio performs EPSS/KEV lookups for a CVE and builds a VulnPrio
// struct with enrichment data and risk score. Used by both JSON and SARIF
// enrichment paths.
func (e *Enricher) buildVulnPrio(cveID, severity string, cvssBase float64) *types.VulnPrio {
	var epssData *types.EPSSData
	var kevData *types.KEVData
	var epssEntry *types.EPSSEntry
	var kevEntry *types.KEVEntry

	if e.epss != nil {
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

	if e.kev != nil {
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

	var risk *float64
	if e.epss != nil && e.kev != nil {
		r := RiskScoreWithCVSSBase(epssEntry, kevEntry, severity, cvssBase)
		risk = &r
	}

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
	return vulnPrio
}
