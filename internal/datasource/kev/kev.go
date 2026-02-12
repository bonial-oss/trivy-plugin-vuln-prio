// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package kev

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/cache"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/types"
)

const (
	cacheFilename   = "known_exploited_vulnerabilities.json"
	primaryURL      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	fallbackURL     = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"
	maxResponseSize = 50 * 1024 * 1024 // 50 MB
)

var httpClient = &http.Client{Timeout: 60 * time.Second}

// Source provides access to CISA KEV data with caching support.
type Source struct {
	cache   *cache.Cache
	entries map[string]types.KEVEntry
}

// NewSource creates a new KEV data source with cache stored under cacheDir/kev/.
func NewSource(cacheDir string) *Source {
	return &Source{
		cache:   cache.New(filepath.Join(cacheDir, "kev")),
		entries: make(map[string]types.KEVEntry),
	}
}

// Load fetches KEV data, using cache when appropriate.
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
			return fmt.Errorf("storing KEV data in cache: %w", storeErr)
		}
		return s.parseJSON(data)
	}

	if s.cache.Exists(cacheFilename) {
		fmt.Fprintf(os.Stderr, "warning: failed to download KEV data (%v), using stale cache\n", err)
		return s.loadFromCache()
	}

	return fmt.Errorf("downloading KEV data: %w", err)
}

// Lookup returns the KEV entry for the given CVE ID, or nil if not found.
func (s *Source) Lookup(cveID string) *types.KEVEntry {
	entry, ok := s.entries[cveID]
	if !ok {
		return nil
	}
	return &entry
}

// loadFromCache loads and parses the cached JSON file.
func (s *Source) loadFromCache() error {
	data, err := s.cache.Load(cacheFilename)
	if err != nil {
		return fmt.Errorf("loading KEV data from cache: %w", err)
	}
	return s.parseJSON(data)
}

// download fetches the KEV catalog JSON from the primary URL.
// If the primary URL fails, it falls back to the GitHub mirror.
// If both fail, it returns an error.
func download() ([]byte, error) {
	data, err := downloadFrom(primaryURL)
	if err == nil {
		return data, nil
	}

	data, err2 := downloadFrom(fallbackURL)
	if err2 == nil {
		return data, nil
	}

	return nil, fmt.Errorf("primary (%s): %w; fallback (%s): %v", primaryURL, err, fallbackURL, err2)
}

// downloadFrom downloads the KEV JSON from the given URL.
func downloadFrom(url string) ([]byte, error) {
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return data, nil
}

// parseJSON unmarshals the KEV catalog JSON and populates the entries map.
func (s *Source) parseJSON(data []byte) error {
	s.entries = make(map[string]types.KEVEntry)

	var catalog types.KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return fmt.Errorf("unmarshaling KEV catalog: %w", err)
	}

	for _, vuln := range catalog.Vulnerabilities {
		s.entries[vuln.CVEID] = vuln
	}

	return nil
}
