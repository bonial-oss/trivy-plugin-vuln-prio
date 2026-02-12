// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

// VulnPrio holds the enrichment data added by the plugin to each
// vulnerability.
type VulnPrio struct {
	Risk *float64  `json:"risk,omitempty"`
	EPSS *EPSSData `json:"epss,omitempty"`
	KEV  *KEVData  `json:"kev,omitempty"`
}

// EPSSData holds the EPSS score and percentile for a CVE.
type EPSSData struct {
	Score        *float64 `json:"score"`
	Percentile   *float64 `json:"percentile"`
	ModelVersion string   `json:"modelVersion,omitempty"`
	ScoreDate    string   `json:"scoreDate,omitempty"`
}

// KEVData holds the Known Exploited Vulnerability data for a CVE.
type KEVData struct {
	Listed                     bool   `json:"listed"`
	DateAdded                  string `json:"dateAdded,omitempty"`
	DueDate                    string `json:"dueDate,omitempty"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse,omitempty"`
	VendorProject              string `json:"vendorProject,omitempty"`
	Product                    string `json:"product,omitempty"`
}

// EPSSEntry represents a single row from the EPSS CSV feed.
type EPSSEntry struct {
	CVE        string
	Score      float64
	Percentile float64
}

// KEVEntry represents a single entry in the CISA KEV catalog JSON.
type KEVEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// KEVCatalog represents the CISA KEV catalog JSON structure.
type KEVCatalog struct {
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}
