// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const minimalTrivyJSON = `{
    "SchemaVersion": 2,
    "ArtifactName": "test:latest",
    "ArtifactType": "container_image",
    "Results": [{
        "Target": "test:latest",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "libfoo",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH"
        }]
    }]
}`

const minimalSARIF = `{
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Trivy"}},
        "results": [{
            "ruleId": "CVE-2024-0001",
            "level": "error",
            "message": {"text": "test"}
        }]
    }]
}`

func requireExitError(t *testing.T, err error, wantCode int) {
	t.Helper()
	var exitErr *ExitError
	require.ErrorAs(t, err, &exitErr)
	assert.Equal(t, wantCode, exitErr.Code)
}

func TestRunWithIO_EmptyStdin(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "",
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(""), &stdout)

	requireExitError(t, err, 2)
	assert.Contains(t, err.Error(), "no input provided on stdin")
}

func TestRunWithIO_InvalidInput(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "",
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader("this is not json or sarif"), &stdout)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "parsing input")
}

func TestRunWithIO_JSONFormat_DefaultOptions(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "",
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(minimalTrivyJSON), &stdout)

	require.NoError(t, err)

	// Verify output is valid JSON.
	var report types.Report
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report), "output should be valid JSON")

	// Verify the vulnerability has a VulnPrio field (empty since both sources disabled).
	require.Len(t, report.Results, 1)
	require.Len(t, report.Results[0].Vulnerabilities, 1)
	vuln := report.Results[0].Vulnerabilities[0]
	assert.Equal(t, "CVE-2024-0001", vuln.VulnerabilityID)
	require.NotNil(t, vuln.VulnPrio, "VulnPrio should be present even with both sources disabled")
}

func TestRunWithIO_SARIFInput_DefaultFormat(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(minimalSARIF), &stdout)

	require.NoError(t, err)

	// Verify output is valid JSON (SARIF is JSON).
	var raw map[string]any
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &raw), "output should be valid JSON")
	assert.Equal(t, "2.1.0", raw["version"], "output should preserve SARIF version")
}

func TestRunWithIO_SARIFInputWithTableFormat(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "table",
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(minimalSARIF), &stdout)

	requireExitError(t, err, 3)
	assert.Contains(t, err.Error(), "--format table requires Trivy JSON input")
}

func TestRunWithIO_HideSuppressed(t *testing.T) {
	// Build a JSON report with ExperimentalModifiedFindings.
	inputJSON := `{
    "SchemaVersion": 2,
    "ArtifactName": "test:latest",
    "ArtifactType": "container_image",
    "Results": [{
        "Target": "test:latest",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "libfoo",
            "InstalledVersion": "1.0.0",
            "Severity": "HIGH"
        }],
        "ExperimentalModifiedFindings": [{
            "Type": "vulnerability",
            "Status": "ignored",
            "Statement": "Not applicable",
            "Source": ".trivyignore",
            "Finding": {
                "VulnerabilityID": "CVE-2024-0002",
                "PkgName": "libbar",
                "InstalledVersion": "2.0.0",
                "Severity": "MEDIUM"
            }
        }]
    }]
}`

	opts := &Options{
		NoEPSS:         true,
		NoKEV:          true,
		Format:         "",
		HideSuppressed: true,
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(inputJSON), &stdout)

	require.NoError(t, err)

	// Parse the output and verify ExperimentalModifiedFindings is absent.
	var report types.Report
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report))
	require.Len(t, report.Results, 1)
	assert.Empty(t, report.Results[0].ExperimentalModifiedFindings,
		"ExperimentalModifiedFindings should be removed when HideSuppressed=true")
}

func TestRunWithIO_OutputToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "output.json")

	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "",
		Output: outPath,
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(minimalTrivyJSON), &stdout)

	require.NoError(t, err)

	// Verify the file was written.
	data, err := os.ReadFile(outPath)
	require.NoError(t, err, "output file should exist")
	assert.NotEmpty(t, data, "output file should not be empty")

	// Verify the file contains valid JSON.
	var report types.Report
	require.NoError(t, json.Unmarshal(data, &report))
	assert.Equal(t, "test:latest", report.ArtifactName)

	// stdout should be empty since output went to file.
	assert.Empty(t, stdout.Bytes(), "stdout should be empty when output is directed to a file")
}

func TestRunWithIO_UnsupportedFormat(t *testing.T) {
	opts := &Options{
		NoEPSS: true,
		NoKEV:  true,
		Format: "xml",
	}
	var stdout bytes.Buffer

	err := runWithIO(opts, strings.NewReader(minimalTrivyJSON), &stdout)

	requireExitError(t, err, 2)
	assert.Contains(t, err.Error(), "unsupported output format: xml")
}
