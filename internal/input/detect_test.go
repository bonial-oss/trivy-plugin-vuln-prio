// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package input

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetect_TrivyJSON(t *testing.T) {
	data := []byte(`{
		"SchemaVersion": 2,
		"ArtifactName": "myimage:latest",
		"ArtifactType": "container_image",
		"Results": [
			{
				"Target": "myimage:latest (alpine 3.18)",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-0001",
						"PkgName": "openssl",
						"InstalledVersion": "3.0.0",
						"Severity": "HIGH"
					}
				]
			}
		]
	}`)

	result, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, FormatJSON, result.Format)
	require.NotNil(t, result.TrivyReport)
	assert.Nil(t, result.SARIFReport)
	assert.Equal(t, 2, result.TrivyReport.SchemaVersion)
	assert.Equal(t, "myimage:latest", result.TrivyReport.ArtifactName)
	require.Len(t, result.TrivyReport.Results, 1)
	require.Len(t, result.TrivyReport.Results[0].Vulnerabilities, 1)
	assert.Equal(t, "CVE-2023-0001", result.TrivyReport.Results[0].Vulnerabilities[0].VulnerabilityID)
}

func TestDetect_SARIF(t *testing.T) {
	data := []byte(`{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": {"driver": {"name": "Trivy"}},
				"results": [
					{
						"ruleId": "CVE-2023-0001",
						"level": "error",
						"message": {"text": "A vulnerability"}
					}
				]
			}
		]
	}`)

	result, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, FormatSARIF, result.Format)
	require.NotNil(t, result.SARIFReport)
	assert.Nil(t, result.TrivyReport)
	assert.Equal(t, "2.1.0", result.SARIFReport.Version)
	require.Len(t, result.SARIFReport.Runs, 1)
	require.Len(t, result.SARIFReport.Runs[0].Results, 1)
	assert.Equal(t, "CVE-2023-0001", result.SARIFReport.Runs[0].Results[0].RuleID)
}

func TestDetect_SARIF_VersionOnly(t *testing.T) {
	// SARIF detected by version alone (no $schema)
	data := []byte(`{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {"driver": {"name": "Trivy"}},
				"results": []
			}
		]
	}`)

	result, err := Parse(data)
	require.NoError(t, err)

	assert.Equal(t, FormatSARIF, result.Format)
	require.NotNil(t, result.SARIFReport)
}

func TestDetect_Invalid(t *testing.T) {
	data := []byte(`this is not json`)

	result, err := Parse(data)
	require.Error(t, err)
	assert.Nil(t, result)
}

func TestDetect_UnrecognizedJSON(t *testing.T) {
	data := []byte(`{"foo": "bar", "baz": 42}`)

	result, err := Parse(data)
	require.Error(t, err)
	assert.Nil(t, result)
}
