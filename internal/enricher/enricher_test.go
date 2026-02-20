// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package enricher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/epss"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/kev"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

// Sample EPSS CSV with 3 entries:
//   - CVE-2024-1234: 0.97 (in both EPSS and KEV fixtures)
//   - CVE-2023-5678: 0.42 (in EPSS only, not in KEV fixture below)
//   - CVE-2023-9012: 0.01
const testEPSSCSV = `#model_version:v2025.03.14,score_date:2026-02-12T00:00:00+0000
cve,epss,percentile
CVE-2024-1234,0.97000,0.99800
CVE-2023-5678,0.42000,0.87300
CVE-2023-9012,0.01000,0.12100
`

// Sample KEV JSON with only CVE-2024-1234.
// CVE-2023-5678 is intentionally excluded so tests can exercise the
// "in EPSS but not in KEV" path.
const testKEVJSON = `{
  "catalogVersion": "2026.02.12",
  "dateReleased": "2026-02-12T00:00:00.000Z",
  "count": 1,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-1234",
      "vendorProject": "ExampleVendor",
      "product": "ExampleProduct",
      "vulnerabilityName": "Example Vulnerability",
      "dateAdded": "2024-01-15",
      "shortDescription": "An example vulnerability.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2024-02-05",
      "knownRansomwareCampaignUse": "Known",
      "notes": "",
      "cwes": ["CWE-78"]
    }
  ]
}`

// setupEPSSSource creates an EPSS source loaded from cache with test data.
func setupEPSSSource(t *testing.T) *epss.Source {
	t.Helper()
	tmpDir := t.TempDir()
	epssDir := filepath.Join(tmpDir, "epss")
	require.NoError(t, os.MkdirAll(epssDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(epssDir, "epss_scores.csv"), []byte(testEPSSCSV), 0o644))
	writeMetadata(t, epssDir)

	s := epss.NewSource(tmpDir)
	require.NoError(t, s.Load(true))
	return s
}

// setupKEVSource creates a KEV source loaded from cache with test data.
func setupKEVSource(t *testing.T) *kev.Source {
	t.Helper()
	tmpDir := t.TempDir()
	kevDir := filepath.Join(tmpDir, "kev")
	require.NoError(t, os.MkdirAll(kevDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(kevDir, "known_exploited_vulnerabilities.json"), []byte(testKEVJSON), 0o644))
	writeMetadata(t, kevDir)

	s := kev.NewSource(tmpDir)
	require.NoError(t, s.Load(true))
	return s
}

// writeMetadata writes a fresh metadata.json to the given directory.
func writeMetadata(t *testing.T, dir string) {
	t.Helper()
	meta := struct {
		DownloadedAt string `json:"downloaded_at"`
	}{
		DownloadedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "metadata.json"), data, 0o644))
}

// makeReport builds a Trivy report with the given vulnerabilities in a single result.
func makeReport(vulns ...types.Vulnerability) *types.Report {
	return &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test-artifact",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target:          "test-target",
				Class:           "os-pkgs",
				Type:            "debian",
				Vulnerabilities: vulns,
			},
		},
	}
}

// testVulns returns 3 test vulnerabilities:
//
//	CVE-2024-1234 (CRITICAL) - in both EPSS and KEV
//	CVE-2023-5678 (HIGH)     - in EPSS only
//	CVE-2023-9999 (MEDIUM)   - in neither
func testVulns() []types.Vulnerability {
	return []types.Vulnerability{
		{
			VulnerabilityID:  "CVE-2024-1234",
			PkgName:          "libexample",
			InstalledVersion: "1.0.0",
			FixedVersion:     "1.1.0",
			Severity:         "CRITICAL",
		},
		{
			VulnerabilityID:  "CVE-2023-5678",
			PkgName:          "libanother",
			InstalledVersion: "2.0.0",
			FixedVersion:     "2.1.0",
			Severity:         "HIGH",
		},
		{
			VulnerabilityID:  "CVE-2023-9999",
			PkgName:          "libunknown",
			InstalledVersion: "3.0.0",
			Severity:         "MEDIUM",
		},
	}
}

func TestEnrich_BothSources(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	result, err := enricher.Enrich(report, Config{})
	require.NoError(t, err)

	vulns := result.Report.Results[0].Vulnerabilities
	require.Len(t, vulns, 3)

	// CVE-2024-1234: in both EPSS (0.97) and KEV (Known).
	v0 := vulns[0]
	require.NotNil(t, v0.VulnPrio)
	require.NotNil(t, v0.VulnPrio.EPSS)
	require.NotNil(t, v0.VulnPrio.EPSS.Score)
	assert.InEpsilon(t, 0.97, *v0.VulnPrio.EPSS.Score, 0.01)
	require.NotNil(t, v0.VulnPrio.EPSS.Percentile)
	assert.InEpsilon(t, 0.998, *v0.VulnPrio.EPSS.Percentile, 0.01)
	assert.Equal(t, "v2025.03.14", v0.VulnPrio.EPSS.ModelVersion)
	assert.Equal(t, "2026-02-12T00:00:00+0000", v0.VulnPrio.EPSS.ScoreDate)
	require.NotNil(t, v0.VulnPrio.KEV)
	assert.True(t, v0.VulnPrio.KEV.Listed)
	assert.Equal(t, "Known", v0.VulnPrio.KEV.KnownRansomwareCampaignUse)
	assert.Equal(t, "ExampleVendor", v0.VulnPrio.KEV.VendorProject)
	assert.Equal(t, "ExampleProduct", v0.VulnPrio.KEV.Product)
	assert.Equal(t, "2024-01-15", v0.VulnPrio.KEV.DateAdded)
	assert.Equal(t, "2024-02-05", v0.VulnPrio.KEV.DueDate)
	require.NotNil(t, v0.VulnPrio.Risk)
	assert.Greater(t, *v0.VulnPrio.Risk, 0.0)

	// CVE-2023-5678: in EPSS only (0.42), not in KEV.
	v1 := vulns[1]
	require.NotNil(t, v1.VulnPrio)
	require.NotNil(t, v1.VulnPrio.EPSS)
	require.NotNil(t, v1.VulnPrio.EPSS.Score)
	assert.InEpsilon(t, 0.42, *v1.VulnPrio.EPSS.Score, 0.01)
	require.NotNil(t, v1.VulnPrio.KEV)
	assert.False(t, v1.VulnPrio.KEV.Listed)
	require.NotNil(t, v1.VulnPrio.Risk)

	// CVE-2023-9999: in neither EPSS nor KEV.
	v2 := vulns[2]
	require.NotNil(t, v2.VulnPrio)
	require.NotNil(t, v2.VulnPrio.EPSS)
	assert.Nil(t, v2.VulnPrio.EPSS.Score)
	require.NotNil(t, v2.VulnPrio.KEV)
	assert.False(t, v2.VulnPrio.KEV.Listed)
	require.NotNil(t, v2.VulnPrio.Risk)
	assert.InDelta(t, 0.0, *v2.VulnPrio.Risk, 0.01)
}

func TestEnrich_NoEPSS(t *testing.T) {
	kevSource := setupKEVSource(t)
	// No EPSS source provided, simulating --no-epss.
	enricher := New(nil, kevSource)

	report := makeReport(testVulns()...)
	result, err := enricher.Enrich(report, Config{})
	require.NoError(t, err)

	for _, vuln := range result.Report.Results[0].Vulnerabilities {
		require.NotNil(t, vuln.VulnPrio, "%s: VulnPrio is nil", vuln.VulnerabilityID)
		assert.Nil(t, vuln.VulnPrio.EPSS, "%s: EPSS should be nil when NoEPSS=true", vuln.VulnerabilityID)
		assert.Nil(t, vuln.VulnPrio.Risk, "%s: Risk should be nil when EPSS disabled", vuln.VulnerabilityID)
	}

	// KEV should still be populated.
	v0 := result.Report.Results[0].Vulnerabilities[0]
	require.NotNil(t, v0.VulnPrio.KEV, "CVE-2024-1234: KEV should be present when NoEPSS=true")
	assert.True(t, v0.VulnPrio.KEV.Listed)
}

func TestEnrich_NoKEV(t *testing.T) {
	epssSource := setupEPSSSource(t)
	// No KEV source provided, simulating --no-kev.
	enricher := New(epssSource, nil)

	report := makeReport(testVulns()...)
	result, err := enricher.Enrich(report, Config{})
	require.NoError(t, err)

	for _, vuln := range result.Report.Results[0].Vulnerabilities {
		require.NotNil(t, vuln.VulnPrio, "%s: VulnPrio is nil", vuln.VulnerabilityID)
		assert.Nil(t, vuln.VulnPrio.KEV, "%s: KEV should be nil when NoKEV=true", vuln.VulnerabilityID)
		assert.Nil(t, vuln.VulnPrio.Risk, "%s: Risk should be nil when KEV disabled", vuln.VulnerabilityID)
	}

	// EPSS should still be populated.
	v0 := result.Report.Results[0].Vulnerabilities[0]
	require.NotNil(t, v0.VulnPrio.EPSS, "CVE-2024-1234: EPSS should be present when NoKEV=true")
	require.NotNil(t, v0.VulnPrio.EPSS.Score)
	assert.InEpsilon(t, 0.97, *v0.VulnPrio.EPSS.Score, 0.01)
}

func TestEnrich_FilterEPSSThreshold(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	// EPSSThreshold=0.5: only vulns with EPSS score >= 0.5 survive.
	// CVE-2024-1234 has 0.97 (passes), CVE-2023-5678 has 0.42 (removed),
	// CVE-2023-9999 has nil score (removed).
	result, err := enricher.Enrich(report, Config{EPSSThreshold: 0.5})
	require.NoError(t, err)

	vulns := result.Report.Results[0].Vulnerabilities
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2024-1234", vulns[0].VulnerabilityID)
}

func TestEnrich_FilterKEVOnly(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	// KEVOnly=true: only KEV-listed vulns survive.
	// Only CVE-2024-1234 is in KEV.
	result, err := enricher.Enrich(report, Config{KEVOnly: true})
	require.NoError(t, err)

	vulns := result.Report.Results[0].Vulnerabilities
	require.Len(t, vulns, 1)
	assert.Equal(t, "CVE-2024-1234", vulns[0].VulnerabilityID)
	assert.True(t, vulns[0].VulnPrio.KEV.Listed, "surviving vuln should have KEV.Listed=true")
}

func TestEnrich_PolicyFailOnKEV(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	result, err := enricher.Enrich(report, Config{FailOnKEV: true})
	require.NoError(t, err)

	assert.True(t, result.PolicyViolation, "expected PolicyViolation=true when FailOnKEV=true and KEV vuln present")

	// All vulns should still be present (policy doesn't filter).
	vulns := result.Report.Results[0].Vulnerabilities
	assert.Len(t, vulns, 3, "expected 3 vulns (policy doesn't filter)")
}

func TestEnrich_PolicyFailOnEPSSThreshold(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	// FailOnEPSSThreshold=0.5: CVE-2024-1234 has 0.97 >= 0.5 -> violation.
	result, err := enricher.Enrich(report, Config{FailOnEPSSThreshold: 0.5})
	require.NoError(t, err)

	assert.True(t, result.PolicyViolation, "expected PolicyViolation=true when FailOnEPSSThreshold=0.5 and vuln with EPSS >= 0.5 present")

	// All vulns should still be present (policy doesn't filter).
	vulns := result.Report.Results[0].Vulnerabilities
	assert.Len(t, vulns, 3, "expected 3 vulns (policy doesn't filter)")
}

func TestEnrich_ModifiedFindings(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	// Add a suppressed finding with a CVE that's in both EPSS and KEV.
	report.Results[0].ExperimentalModifiedFindings = []types.ModifiedFinding{
		{
			Type:      "vulnerability",
			Status:    "ignored",
			Statement: "Not applicable",
			Source:    ".trivyignore",
			Finding: types.Vulnerability{
				VulnerabilityID:  "CVE-2024-1234",
				PkgName:          "libexample",
				InstalledVersion: "1.0.0",
				Severity:         "CRITICAL",
			},
		},
	}

	result, err := enricher.Enrich(report, Config{})
	require.NoError(t, err)

	mf := result.Report.Results[0].ExperimentalModifiedFindings
	require.Len(t, mf, 1)

	finding := mf[0].Finding
	require.NotNil(t, finding.VulnPrio, "suppressed finding should be enriched with VulnPrio")
	require.NotNil(t, finding.VulnPrio.EPSS)
	require.NotNil(t, finding.VulnPrio.EPSS.Score)
	assert.InEpsilon(t, 0.97, *finding.VulnPrio.EPSS.Score, 0.01)
	require.NotNil(t, finding.VulnPrio.KEV)
	assert.True(t, finding.VulnPrio.KEV.Listed)
	require.NotNil(t, finding.VulnPrio.Risk)
	assert.Greater(t, *finding.VulnPrio.Risk, 0.0)
}

func TestEnrich_ModifiedFindings_NotFiltered(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	report := makeReport(testVulns()...)
	// Add a suppressed finding with low EPSS score.
	report.Results[0].ExperimentalModifiedFindings = []types.ModifiedFinding{
		{
			Type:      "vulnerability",
			Status:    "ignored",
			Statement: "Low risk",
			Source:    ".trivyignore",
			Finding: types.Vulnerability{
				VulnerabilityID:  "CVE-2023-5678",
				PkgName:          "libanother",
				InstalledVersion: "2.0.0",
				Severity:         "HIGH",
			},
		},
	}

	// EPSSThreshold=0.5 should filter regular vulns but NOT suppressed ones.
	result, err := enricher.Enrich(report, Config{EPSSThreshold: 0.5})
	require.NoError(t, err)

	// Regular vulns filtered: only CVE-2024-1234 survives (0.97 >= 0.5).
	vulns := result.Report.Results[0].Vulnerabilities
	require.Len(t, vulns, 1)

	// Suppressed finding should NOT be filtered (CVE-2023-5678 has EPSS 0.42 < 0.5).
	mf := result.Report.Results[0].ExperimentalModifiedFindings
	require.Len(t, mf, 1)
	assert.Equal(t, "CVE-2023-5678", mf[0].Finding.VulnerabilityID)
}

func TestEnrich_ModifiedFindings_NoPolicyViolation(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// Report with NO regular vulns, only a suppressed KEV vuln.
	report := &types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test-artifact",
		ArtifactType:  "container_image",
		Results: []types.Result{
			{
				Target: "test-target",
				Type:   "debian",
				ExperimentalModifiedFindings: []types.ModifiedFinding{
					{
						Type:      "vulnerability",
						Status:    "ignored",
						Statement: "Accepted risk",
						Source:    ".trivyignore",
						Finding: types.Vulnerability{
							VulnerabilityID:  "CVE-2024-1234",
							PkgName:          "libexample",
							InstalledVersion: "1.0.0",
							Severity:         "CRITICAL",
						},
					},
				},
			},
		},
	}

	result, err := enricher.Enrich(report, Config{FailOnKEV: true})
	require.NoError(t, err)

	// Suppressed KEV vulns should NOT trigger policy violation.
	assert.False(t, result.PolicyViolation, "expected PolicyViolation=false: suppressed vulns should not trigger policy")

	// But the suppressed finding should still be enriched.
	mf := result.Report.Results[0].ExperimentalModifiedFindings
	require.Len(t, mf, 1)
	require.NotNil(t, mf[0].Finding.VulnPrio)
	require.NotNil(t, mf[0].Finding.VulnPrio.KEV)
	assert.True(t, mf[0].Finding.VulnPrio.KEV.Listed, "suppressed finding should be enriched with KEV.Listed=true")
}

func TestEnrich_NoPolicyViolation(t *testing.T) {
	epssSource := setupEPSSSource(t)
	kevSource := setupKEVSource(t)
	enricher := New(epssSource, kevSource)

	// Report with only CVE-2023-9999 which is in neither EPSS nor KEV.
	report := makeReport(types.Vulnerability{
		VulnerabilityID:  "CVE-2023-9999",
		PkgName:          "libunknown",
		InstalledVersion: "3.0.0",
		Severity:         "MEDIUM",
	})

	result, err := enricher.Enrich(report, Config{FailOnKEV: true, FailOnEPSSThreshold: 0.5})
	require.NoError(t, err)

	assert.False(t, result.PolicyViolation, "expected PolicyViolation=false when no KEV vulns and no EPSS scores above threshold")
}
