// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnerability_RoundTrip_PreservesExtras(t *testing.T) {
	input := `{
		"VulnerabilityID": "CVE-2023-1234",
		"PkgName": "libfoo",
		"InstalledVersion": "1.0.0",
		"FixedVersion": "1.1.0",
		"Severity": "HIGH",
		"CVSS": {"nvd": {"V3Score": 7.5}},
		"Title": "Buffer overflow in libfoo",
		"Description": "A buffer overflow vulnerability exists in libfoo before 1.1.0.",
		"References": ["https://cve.example.com/CVE-2023-1234"],
		"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234",
		"PublishedDate": "2023-06-15T00:00:00Z",
		"LastModifiedDate": "2023-06-20T00:00:00Z",
		"Status": 3
	}`

	var v Vulnerability
	require.NoError(t, json.Unmarshal([]byte(input), &v))

	// Verify known fields are accessible.
	assert.Equal(t, "CVE-2023-1234", v.VulnerabilityID)
	assert.Equal(t, "libfoo", v.PkgName)
	assert.Equal(t, "1.0.0", v.InstalledVersion)
	assert.Equal(t, "1.1.0", v.FixedVersion)
	assert.Equal(t, "HIGH", v.Severity)
	assert.NotNil(t, v.CVSS)
	assert.Nil(t, v.VulnPrio)

	// Verify extras captured unknown fields.
	expectedExtras := []string{
		"Title", "Description", "References", "PrimaryURL",
		"PublishedDate", "LastModifiedDate", "Status",
	}
	for _, key := range expectedExtras {
		assert.Contains(t, v.Extras, key)
	}

	// Re-marshal and verify round-trip.
	out, err := json.Marshal(v)
	require.NoError(t, err)

	var roundTrip map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	// All original fields must be present.
	allExpected := []string{
		"VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion",
		"Severity", "CVSS", "Title", "Description", "References",
		"PrimaryURL", "PublishedDate", "LastModifiedDate", "Status",
	}
	for _, key := range allExpected {
		assert.Contains(t, roundTrip, key)
	}

	// VulnPrio should NOT be in output when nil.
	assert.NotContains(t, roundTrip, "VulnPrio")
}

func TestVulnerability_Marshal_WithVulnPrio(t *testing.T) {
	score := 0.85
	percentile := 0.95
	risk := 8.5

	v := Vulnerability{
		VulnerabilityID:  "CVE-2024-5678",
		PkgName:          "libbar",
		InstalledVersion: "2.0.0",
		FixedVersion:     "2.1.0",
		Severity:         "CRITICAL",
		VulnPrio: &VulnPrio{
			Risk: &risk,
			EPSS: &EPSSData{
				Score:      &score,
				Percentile: &percentile,
			},
			KEV: &KEVData{
				Listed:    true,
				DateAdded: "2024-01-15",
			},
		},
		Extras: map[string]json.RawMessage{
			"Title":       json.RawMessage(`"Critical flaw in libbar"`),
			"Description": json.RawMessage(`"A critical vulnerability."`),
		},
	}

	out, err := json.Marshal(v)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	// VulnPrio must be present.
	vulnPrioRaw, ok := result["VulnPrio"]
	require.True(t, ok, "VulnPrio missing from output")

	var vp VulnPrio
	require.NoError(t, json.Unmarshal(vulnPrioRaw, &vp))
	require.NotNil(t, vp.Risk)
	assert.Equal(t, 8.5, *vp.Risk)
	require.NotNil(t, vp.EPSS)
	require.NotNil(t, vp.EPSS.Score)
	assert.Equal(t, 0.85, *vp.EPSS.Score)
	require.NotNil(t, vp.KEV)
	assert.True(t, vp.KEV.Listed)

	// Original extra fields must also survive.
	assert.Contains(t, result, "Title")
	assert.Contains(t, result, "Description")

	// Known fields present.
	assert.Contains(t, result, "VulnerabilityID")
	assert.Contains(t, result, "Severity")
}

func TestReport_RoundTrip_EnrichAndPreserve(t *testing.T) {
	input := `{
		"SchemaVersion": 2,
		"ArtifactName": "myimage:latest",
		"ArtifactType": "container_image",
		"Metadata": {"ImageID": "sha256:abc123"},
		"Results": [
			{
				"Target": "myimage:latest (alpine 3.18)",
				"Class": "os-pkgs",
				"Type": "alpine",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-0001",
						"PkgName": "openssl",
						"InstalledVersion": "3.0.0",
						"FixedVersion": "3.0.1",
						"Severity": "HIGH",
						"Title": "OpenSSL vulnerability",
						"Description": "A flaw in OpenSSL.",
						"References": ["https://example.com/cve-2023-0001"],
						"PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-0001",
						"CVSS": {"nvd": {"V3Score": 8.1}}
					},
					{
						"VulnerabilityID": "CVE-2023-0002",
						"PkgName": "curl",
						"InstalledVersion": "7.80.0",
						"Severity": "MEDIUM",
						"Title": "Curl issue",
						"SeveritySource": "nvd"
					}
				],
				"Packages": [{"Name": "openssl"}, {"Name": "curl"}]
			}
		]
	}`

	var report Report
	require.NoError(t, json.Unmarshal([]byte(input), &report))

	// Verify basic structure.
	assert.Equal(t, 2, report.SchemaVersion)
	assert.Equal(t, "myimage:latest", report.ArtifactName)
	require.Len(t, report.Results, 1)
	require.Len(t, report.Results[0].Vulnerabilities, 2)

	// Enrich the first vulnerability.
	score := 0.5
	percentile := 0.7
	risk := 6.0
	report.Results[0].Vulnerabilities[0].VulnPrio = &VulnPrio{
		Risk: &risk,
		EPSS: &EPSSData{
			Score:      &score,
			Percentile: &percentile,
		},
	}

	// Marshal back.
	out, err := json.Marshal(report)
	require.NoError(t, err)

	// Re-parse to verify.
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	// Top-level fields.
	assert.Contains(t, result, "Metadata")

	// Parse Results.
	var results []json.RawMessage
	require.NoError(t, json.Unmarshal(result["Results"], &results))
	require.Len(t, results, 1)

	var resultObj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(results[0], &resultObj))

	// Packages passthrough.
	assert.Contains(t, resultObj, "Packages")

	// Parse Vulnerabilities.
	var vulns []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resultObj["Vulnerabilities"], &vulns))
	require.Len(t, vulns, 2)

	// First vulnerability: enriched with VulnPrio, original fields preserved.
	vuln0 := vulns[0]
	assert.Contains(t, vuln0, "VulnPrio")
	assert.Contains(t, vuln0, "Title")
	assert.Contains(t, vuln0, "Description")
	assert.Contains(t, vuln0, "References")
	assert.Contains(t, vuln0, "PrimaryURL")
	assert.Contains(t, vuln0, "CVSS")

	// Second vulnerability: no VulnPrio, extras preserved.
	vuln1 := vulns[1]
	assert.NotContains(t, vuln1, "VulnPrio")
	assert.Contains(t, vuln1, "Title")
	assert.Contains(t, vuln1, "SeveritySource")
}

func TestVulnerability_UnmarshalJSON_EmptyExtras(t *testing.T) {
	input := `{
		"VulnerabilityID": "CVE-2023-9999",
		"PkgName": "minimal",
		"InstalledVersion": "0.1.0",
		"Severity": "LOW"
	}`

	var v Vulnerability
	require.NoError(t, json.Unmarshal([]byte(input), &v))

	assert.Equal(t, "CVE-2023-9999", v.VulnerabilityID)
	assert.Empty(t, v.FixedVersion)
	assert.Nil(t, v.Extras)

	// Round-trip should work fine.
	out, err := json.Marshal(v)
	require.NoError(t, err)

	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &result))

	// FixedVersion should be omitted.
	assert.NotContains(t, result, "FixedVersion")
}

func TestResult_RoundTrip_PreservesExtras(t *testing.T) {
	input := `{
		"Target": "myimage:latest",
		"Class": "os-pkgs",
		"Type": "alpine",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2023-0001",
				"PkgName": "openssl",
				"InstalledVersion": "3.0.0",
				"Severity": "HIGH"
			}
		],
		"Packages": [{"Name": "openssl"}],
		"CustomField": "should survive round-trip",
		"AnotherField": 42
	}`

	var r Result
	require.NoError(t, json.Unmarshal([]byte(input), &r))

	assert.Equal(t, "myimage:latest", r.Target)
	require.Len(t, r.Vulnerabilities, 1)
	assert.NotNil(t, r.Packages)

	// Unknown fields captured in Extras.
	assert.Contains(t, r.Extras, "CustomField")
	assert.Contains(t, r.Extras, "AnotherField")

	// Round-trip.
	out, err := json.Marshal(r)
	require.NoError(t, err)

	var roundTrip map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	for _, key := range []string{"Target", "Class", "Type", "Vulnerabilities", "Packages", "CustomField", "AnotherField"} {
		assert.Contains(t, roundTrip, key)
	}
}

func TestResult_RoundTrip_WithModifiedFindings(t *testing.T) {
	input := `{
		"Target": "test:latest",
		"Type": "debian",
		"Vulnerabilities": [
			{
				"VulnerabilityID": "CVE-2024-1111",
				"PkgName": "lib1",
				"InstalledVersion": "1.0",
				"Severity": "HIGH"
			}
		],
		"ExperimentalModifiedFindings": [
			{
				"Type": "vulnerability",
				"Status": "ignored",
				"Statement": "Not applicable",
				"Source": ".trivyignore",
				"Finding": {
					"VulnerabilityID": "CVE-2024-2222",
					"PkgName": "lib2",
					"InstalledVersion": "2.0",
					"Severity": "MEDIUM",
					"Title": "Suppressed vuln title"
				}
			}
		]
	}`

	var r Result
	require.NoError(t, json.Unmarshal([]byte(input), &r))

	require.Len(t, r.ExperimentalModifiedFindings, 1)

	mf := r.ExperimentalModifiedFindings[0]
	assert.Equal(t, "vulnerability", mf.Type)
	assert.Equal(t, "ignored", mf.Status)
	assert.Equal(t, "Not applicable", mf.Statement)
	assert.Equal(t, ".trivyignore", mf.Source)
	assert.Equal(t, "CVE-2024-2222", mf.Finding.VulnerabilityID)

	// Finding's Title should be in Extras.
	assert.Contains(t, mf.Finding.Extras, "Title")

	// Round-trip.
	out, err := json.Marshal(r)
	require.NoError(t, err)

	var roundTrip map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &roundTrip))

	assert.Contains(t, roundTrip, "ExperimentalModifiedFindings")

	// Parse modified findings from round-trip.
	var findings []ModifiedFinding
	require.NoError(t, json.Unmarshal(roundTrip["ExperimentalModifiedFindings"], &findings))
	require.Len(t, findings, 1)
	assert.Equal(t, "CVE-2024-2222", findings[0].Finding.VulnerabilityID)
	// Title should survive round-trip in Finding.Extras.
	assert.Contains(t, findings[0].Finding.Extras, "Title")
}

func TestVulnerability_Unmarshal_WithVulnPrio(t *testing.T) {
	input := `{
		"VulnerabilityID": "CVE-2024-0001",
		"PkgName": "foo",
		"InstalledVersion": "1.0.0",
		"Severity": "CRITICAL",
		"VulnPrio": {
			"risk": 9.5,
			"epss": {"score": 0.9, "percentile": 0.99},
			"kev": {"listed": true, "dateAdded": "2024-01-01"}
		},
		"Title": "Test vuln"
	}`

	var v Vulnerability
	require.NoError(t, json.Unmarshal([]byte(input), &v))

	require.NotNil(t, v.VulnPrio)
	require.NotNil(t, v.VulnPrio.Risk)
	assert.Equal(t, 9.5, *v.VulnPrio.Risk)
	require.NotNil(t, v.VulnPrio.EPSS)
	require.NotNil(t, v.VulnPrio.EPSS.Score)
	assert.Equal(t, 0.9, *v.VulnPrio.EPSS.Score)
	require.NotNil(t, v.VulnPrio.KEV)
	assert.True(t, v.VulnPrio.KEV.Listed)

	// Title should be in extras.
	assert.Contains(t, v.Extras, "Title")
}
