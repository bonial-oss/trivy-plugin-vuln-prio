// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package epss

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

const sampleCSV = `#model_version:v2025.03.14,score_date:2026-02-12T00:00:00+0000
cve,epss,percentile
CVE-2024-1234,0.97000,0.99800
CVE-2023-5678,0.42000,0.87300
CVE-2023-9012,0.01000,0.12100
`

func TestParseCSV(t *testing.T) {
	s := &Source{entries: make(map[string]types.EPSSEntry)}
	require.NoError(t, s.parseCSV([]byte(sampleCSV)))

	require.Len(t, s.entries, 3)

	tests := []struct {
		cve        string
		score      float64
		percentile float64
	}{
		{"CVE-2024-1234", 0.97, 0.998},
		{"CVE-2023-5678", 0.42, 0.873},
		{"CVE-2023-9012", 0.01, 0.121},
	}

	for _, tc := range tests {
		entry, ok := s.entries[tc.cve]
		require.True(t, ok, "entry for %s not found", tc.cve)
		assert.InEpsilon(t, tc.score, entry.Score, 1e-9)
		assert.InEpsilon(t, tc.percentile, entry.Percentile, 1e-9)
		assert.Equal(t, tc.cve, entry.CVE)
	}

	assert.Equal(t, "v2025.03.14", s.ModelVersion())
	assert.Equal(t, "2026-02-12T00:00:00+0000", s.ScoreDate())
}

func TestParseCSV_Empty(t *testing.T) {
	emptyCSV := `#model_version:v2025.03.14,score_date:2026-02-12T00:00:00+0000
cve,epss,percentile
`
	s := &Source{entries: make(map[string]types.EPSSEntry)}
	require.NoError(t, s.parseCSV([]byte(emptyCSV)))

	assert.Empty(t, s.entries)
}

func TestLookup(t *testing.T) {
	s := &Source{entries: make(map[string]types.EPSSEntry)}
	require.NoError(t, s.parseCSV([]byte(sampleCSV)))

	// Look up a known CVE.
	entry := s.Lookup("CVE-2024-1234")
	require.NotNil(t, entry)
	assert.InEpsilon(t, 0.97, entry.Score, 1e-9)
	assert.InEpsilon(t, 0.998, entry.Percentile, 1e-9)

	// Look up an unknown CVE.
	entry = s.Lookup("CVE-9999-0000")
	assert.Nil(t, entry)
}

func TestSource_Load_FromCache(t *testing.T) {
	tmpDir := t.TempDir()
	epssDir := filepath.Join(tmpDir, "epss")
	require.NoError(t, os.MkdirAll(epssDir, 0o755))

	// Write the sample CSV to the cache location.
	require.NoError(t, os.WriteFile(filepath.Join(epssDir, cacheFilename), []byte(sampleCSV), 0o644))

	// Write a fresh metadata.json so the cache is considered valid.
	meta := struct {
		DownloadedAt string `json:"downloaded_at"`
	}{
		DownloadedAt: time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, err := json.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(epssDir, "metadata.json"), metaBytes, 0o644))

	// Create the source pointing at our tmp dir.
	s := NewSource(tmpDir)

	// Load with skipUpdate=true -- should load from cache without any network calls.
	require.NoError(t, s.Load(true))

	// Verify entries were loaded.
	require.Len(t, s.entries, 3)

	entry := s.Lookup("CVE-2024-1234")
	require.NotNil(t, entry)
	assert.InEpsilon(t, 0.97, entry.Score, 1e-9)

	assert.Equal(t, "v2025.03.14", s.ModelVersion())
	assert.Equal(t, "2026-02-12T00:00:00+0000", s.ScoreDate())
}
