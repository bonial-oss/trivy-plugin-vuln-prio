// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCache_IsFresh_NoMetadata(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	assert.False(t, c.IsFresh(), "IsFresh() = true, want false when no metadata file exists")
}

func TestCache_IsFresh_Stale(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	// Write metadata with a timestamp older than 24 hours.
	staleTime := time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339)
	meta := Metadata{DownloadedAt: staleTime}
	metaBytes, err := json.Marshal(meta)
	require.NoError(t, err, "failed to marshal metadata")
	err = os.WriteFile(filepath.Join(dir, "metadata.json"), metaBytes, 0o644)
	require.NoError(t, err, "failed to write metadata")

	assert.False(t, c.IsFresh(), "IsFresh() = true, want false when metadata is older than 24 hours")
}

func TestCache_IsFresh_Fresh(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	// Write metadata with a recent timestamp.
	freshTime := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
	meta := Metadata{DownloadedAt: freshTime}
	metaBytes, err := json.Marshal(meta)
	require.NoError(t, err, "failed to marshal metadata")
	err = os.WriteFile(filepath.Join(dir, "metadata.json"), metaBytes, 0o644)
	require.NoError(t, err, "failed to write metadata")

	assert.True(t, c.IsFresh(), "IsFresh() = false, want true when metadata is less than 24 hours old")
}

func TestCache_Store(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	data := []byte("test data content")
	filename := "testfile.csv"

	require.NoError(t, c.Store(filename, data), "Store() error")

	// Verify data file was written.
	dataPath := filepath.Join(dir, filename)
	got, err := os.ReadFile(dataPath)
	require.NoError(t, err, "failed to read stored data file")
	assert.Equal(t, string(data), string(got))

	// Verify metadata file was written.
	metaPath := filepath.Join(dir, "metadata.json")
	metaBytes, err := os.ReadFile(metaPath)
	require.NoError(t, err, "failed to read metadata file")
	var meta Metadata
	require.NoError(t, json.Unmarshal(metaBytes, &meta), "failed to unmarshal metadata")
	assert.NotEmpty(t, meta.DownloadedAt)

	// Verify the timestamp is recent (within the last minute).
	downloadedAt, err := time.Parse(time.RFC3339, meta.DownloadedAt)
	require.NoError(t, err, "failed to parse downloaded_at")
	assert.WithinDuration(t, time.Now(), downloadedAt, time.Minute)
}

func TestCache_Load(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	data := []byte("cached content here")
	filename := "data.json"

	require.NoError(t, c.Store(filename, data), "Store() error")

	got, err := c.Load(filename)
	require.NoError(t, err, "Load() error")
	assert.Equal(t, string(data), string(got))
}

func TestCache_Load_NoCachedFile(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	_, err := c.Load("nonexistent.csv")
	assert.Error(t, err, "Load() error = nil, want error when file does not exist")
}

func TestCache_Exists(t *testing.T) {
	dir := t.TempDir()
	c := New(dir)

	filename := "data.csv"

	// Before storing, Exists should return false.
	assert.False(t, c.Exists(filename), "Exists() = true before Store, want false")

	// After storing, Exists should return true.
	require.NoError(t, c.Store(filename, []byte("some data")), "Store() error")

	assert.True(t, c.Exists(filename), "Exists() = false after Store, want true")
}
