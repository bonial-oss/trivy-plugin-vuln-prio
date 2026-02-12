// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package kev

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const sampleJSON = `{
  "catalogVersion": "2026.02.12",
  "dateReleased": "2026-02-12T00:00:00.000Z",
  "count": 2,
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
    },
    {
      "cveID": "CVE-2023-5678",
      "vendorProject": "AnotherVendor",
      "product": "AnotherProduct",
      "vulnerabilityName": "Another Vulnerability",
      "dateAdded": "2023-06-01",
      "shortDescription": "Another example.",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2023-06-22",
      "knownRansomwareCampaignUse": "Unknown",
      "notes": "",
      "cwes": ["CWE-79"]
    }
  ]
}`

func TestParseJSON(t *testing.T) {
	s := &Source{entries: make(map[string]types.KEVEntry)}
	require.NoError(t, s.parseJSON([]byte(sampleJSON)))
	require.Len(t, s.entries, 2)

	tests := []struct {
		cveID                      string
		vendorProject              string
		product                    string
		dateAdded                  string
		dueDate                    string
		knownRansomwareCampaignUse string
	}{
		{
			cveID:                      "CVE-2024-1234",
			vendorProject:              "ExampleVendor",
			product:                    "ExampleProduct",
			dateAdded:                  "2024-01-15",
			dueDate:                    "2024-02-05",
			knownRansomwareCampaignUse: "Known",
		},
		{
			cveID:                      "CVE-2023-5678",
			vendorProject:              "AnotherVendor",
			product:                    "AnotherProduct",
			dateAdded:                  "2023-06-01",
			dueDate:                    "2023-06-22",
			knownRansomwareCampaignUse: "Unknown",
		},
	}

	for _, tc := range tests {
		entry, ok := s.entries[tc.cveID]
		require.True(t, ok, "entry for %s not found", tc.cveID)
		assert.Equal(t, tc.cveID, entry.CVEID)
		assert.Equal(t, tc.vendorProject, entry.VendorProject)
		assert.Equal(t, tc.product, entry.Product)
		assert.Equal(t, tc.dateAdded, entry.DateAdded)
		assert.Equal(t, tc.dueDate, entry.DueDate)
		assert.Equal(t, tc.knownRansomwareCampaignUse, entry.KnownRansomwareCampaignUse)
	}
}

func TestLookup_Found(t *testing.T) {
	s := &Source{entries: make(map[string]types.KEVEntry)}
	require.NoError(t, s.parseJSON([]byte(sampleJSON)))

	entry := s.Lookup("CVE-2024-1234")
	require.NotNil(t, entry)
	assert.Equal(t, "CVE-2024-1234", entry.CVEID)
	assert.Equal(t, "Known", entry.KnownRansomwareCampaignUse)
	assert.Equal(t, "ExampleVendor", entry.VendorProject)
	assert.Equal(t, "ExampleProduct", entry.Product)
	assert.Equal(t, "2024-01-15", entry.DateAdded)
	assert.Equal(t, "2024-02-05", entry.DueDate)
}

func TestLookup_NotFound(t *testing.T) {
	s := &Source{entries: make(map[string]types.KEVEntry)}
	require.NoError(t, s.parseJSON([]byte(sampleJSON)))

	entry := s.Lookup("CVE-9999-0000")
	assert.Nil(t, entry)
}

func TestSource_Load_FromCache(t *testing.T) {
	tmpDir := t.TempDir()
	kevDir := filepath.Join(tmpDir, "kev")
	require.NoError(t, os.MkdirAll(kevDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(kevDir, cacheFilename), []byte(sampleJSON), 0o644))

	// Write a fresh metadata.json so the cache is considered valid.
	meta := struct {
		DownloadedAt string `json:"downloaded_at"`
	}{
		DownloadedAt: time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, err := json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(kevDir, "metadata.json"), metaBytes, 0o644))

	// Create the source pointing at our tmp dir.
	s := NewSource(tmpDir)

	// Load with skipUpdate=true -- should load from cache without any network calls.
	require.NoError(t, s.Load(true))
	require.Len(t, s.entries, 2)

	entry := s.Lookup("CVE-2024-1234")
	require.NotNil(t, entry)
	assert.Equal(t, "Known", entry.KnownRansomwareCampaignUse)
	assert.Equal(t, "ExampleVendor", entry.VendorProject)

	entry2 := s.Lookup("CVE-2023-5678")
	require.NotNil(t, entry2)
	assert.Equal(t, "Unknown", entry2.KnownRansomwareCampaignUse)
}
