// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package epss

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/cache"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const (
	cacheFilename       = "epss_scores.csv"
	baseURL             = "https://epss.empiricalsecurity.com"
	maxDecompressedSize = 100 * 1024 * 1024 // 100 MB
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

// Source provides access to EPSS data with caching support.
type Source struct {
	cache        *cache.Cache
	entries      map[string]types.EPSSEntry
	modelVersion string
	scoreDate    string
}

// NewSource creates a new EPSS data source with cache stored under cacheDir/epss/.
func NewSource(cacheDir string) *Source {
	return &Source{
		cache:   cache.New(filepath.Join(cacheDir, "epss")),
		entries: make(map[string]types.EPSSEntry),
	}
}

// Load fetches EPSS data, using cache when appropriate.
//
// Logic:
//  1. If skipUpdate and cache exists -> load from cache, parse, return.
//  2. If cache is fresh -> load from cache, parse, return.
//  3. Download fresh data.
//  4. If download succeeds -> store in cache, parse, return.
//  5. If download fails and cache exists -> warn to stderr, load stale cache, parse, return.
//  6. If download fails and no cache -> return error.
func (s *Source) Load(skipUpdate bool) error {
	if skipUpdate && s.cache.Exists(cacheFilename) {
		return s.loadFromCache()
	}

	if s.cache.IsFresh() {
		return s.loadFromCache()
	}

	data, err := download()
	if err == nil {
		if storeErr := s.cache.Store(cacheFilename, data); storeErr != nil {
			return fmt.Errorf("storing EPSS data in cache: %w", storeErr)
		}
		return s.parseCSV(data)
	}

	if s.cache.Exists(cacheFilename) {
		fmt.Fprintf(os.Stderr, "warning: failed to download EPSS data (%v), using stale cache\n", err)
		return s.loadFromCache()
	}

	return fmt.Errorf("downloading EPSS data: %w", err)
}

// Lookup returns the EPSS entry for the given CVE ID, or nil if not found.
func (s *Source) Lookup(cveID string) *types.EPSSEntry {
	entry, ok := s.entries[cveID]
	if !ok {
		return nil
	}
	return &entry
}

// ModelVersion returns the model version string from the EPSS CSV header.
func (s *Source) ModelVersion() string {
	return s.modelVersion
}

// ScoreDate returns the score date string from the EPSS CSV header.
func (s *Source) ScoreDate() string {
	return s.scoreDate
}

// loadFromCache loads and parses the cached CSV file.
func (s *Source) loadFromCache() error {
	data, err := s.cache.Load(cacheFilename)
	if err != nil {
		return fmt.Errorf("loading EPSS data from cache: %w", err)
	}
	return s.parseCSV(data)
}

// download fetches the gzip-compressed EPSS CSV for today's date.
// If today's file is not available, it falls back to yesterday's date.
func download() ([]byte, error) {
	now := time.Now().UTC()
	today := now.Format("2006-01-02")
	yesterday := now.AddDate(0, 0, -1).Format("2006-01-02")

	data, err := downloadForDate(today)
	if err == nil {
		return data, nil
	}

	data, err2 := downloadForDate(yesterday)
	if err2 == nil {
		return data, nil
	}

	return nil, fmt.Errorf("today (%s): %w; yesterday (%s): %v", today, err, yesterday, err2)
}

// downloadForDate downloads and decompresses the EPSS CSV for the given date string.
func downloadForDate(date string) ([]byte, error) {
	url := fmt.Sprintf("%s/epss_scores-%s.csv.gz", baseURL, date)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gz.Close()

	data, err := io.ReadAll(io.LimitReader(gz, maxDecompressedSize))
	if err != nil {
		return nil, fmt.Errorf("reading gzip data: %w", err)
	}

	return data, nil
}

// parseCSV parses the EPSS CSV data and populates the entries map.
// It extracts model_version and score_date from the comment header line.
func (s *Source) parseCSV(data []byte) error {
	s.entries = make(map[string]types.EPSSEntry)
	s.modelVersion = ""
	s.scoreDate = ""

	lines := strings.Split(string(data), "\n")

	// Process comment lines starting with '#' to extract metadata.
	dataStart := 0
	for i, line := range lines {
		if !strings.HasPrefix(line, "#") {
			dataStart = i
			break
		}
		s.parseCommentLine(line)
	}

	// Parse the remaining CSV data (header + data rows).
	remaining := strings.Join(lines[dataStart:], "\n")
	reader := csv.NewReader(strings.NewReader(remaining))

	// Read and discard the CSV header line.
	_, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil
		}
		return fmt.Errorf("reading CSV header: %w", err)
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading CSV record: %w", err)
		}

		if len(record) < 3 {
			continue
		}

		score, err := strconv.ParseFloat(record[1], 64)
		if err != nil {
			return fmt.Errorf("parsing EPSS score for %s: %w", record[0], err)
		}

		percentile, err := strconv.ParseFloat(record[2], 64)
		if err != nil {
			return fmt.Errorf("parsing EPSS percentile for %s: %w", record[0], err)
		}

		s.entries[record[0]] = types.EPSSEntry{
			CVE:        record[0],
			Score:      score,
			Percentile: percentile,
		}
	}

	return nil
}

// parseCommentLine extracts metadata from a comment line like:
// #model_version:v2025.03.14,score_date:2026-02-12T00:00:00+0000
func (s *Source) parseCommentLine(line string) {
	line = strings.TrimPrefix(line, "#")
	parts := strings.Split(line, ",")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value := strings.TrimSpace(kv[1])
		switch key {
		case "model_version":
			s.modelVersion = value
		case "score_date":
			s.scoreDate = value
		}
	}
}
