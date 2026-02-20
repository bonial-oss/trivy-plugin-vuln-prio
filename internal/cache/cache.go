// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const defaultTTL = 24 * time.Hour

type Metadata struct {
	DownloadedAt string `json:"downloaded_at"`
}

type Cache struct {
	dir string
	ttl time.Duration
}

func New(dir string) *Cache {
	return &Cache{dir: dir, ttl: defaultTTL}
}

func (c *Cache) IsFresh() bool {
	meta, err := c.loadMetadata()
	if err != nil {
		return false
	}
	downloadedAt, err := time.Parse(time.RFC3339, meta.DownloadedAt)
	if err != nil {
		return false
	}
	return time.Since(downloadedAt) < c.ttl
}

func (c *Cache) Store(filename string, data []byte) error {
	if err := os.MkdirAll(c.dir, 0o755); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	dataPath := filepath.Join(c.dir, filename)
	if err := os.WriteFile(dataPath, data, 0o644); err != nil {
		return fmt.Errorf("writing cache data: %w", err)
	}
	meta := Metadata{DownloadedAt: time.Now().UTC().Format(time.RFC3339)}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshaling metadata: %w", err)
	}
	metaPath := filepath.Join(c.dir, "metadata.json")
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}
	return nil
}

func (c *Cache) Load(filename string) ([]byte, error) {
	return os.ReadFile(filepath.Join(c.dir, filename))
}

func (c *Cache) Exists(filename string) bool {
	_, err := os.Stat(filepath.Join(c.dir, filename))
	return err == nil
}

func (c *Cache) loadMetadata() (*Metadata, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, "metadata.json"))
	if err != nil {
		return nil, err
	}
	var meta Metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}
