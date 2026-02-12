// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

import "encoding/json"

// Report is a minimal representation of Trivy's JSON report output.
// Only fields the plugin reads or passes through are typed; everything
// else is preserved via json.RawMessage.
type Report struct {
	SchemaVersion int             `json:"SchemaVersion"`
	ArtifactName  string          `json:"ArtifactName"`
	ArtifactType  string          `json:"ArtifactType"`
	Metadata      json.RawMessage `json:"Metadata,omitempty"`
	Results       []Result        `json:"Results"`
}

// Result represents a single Trivy scan result for a target.
type Result struct {
	Target            string            `json:"Target"`
	Class             string            `json:"Class,omitempty"`
	Type              string            `json:"Type,omitempty"`
	Vulnerabilities   []Vulnerability   `json:"Vulnerabilities,omitempty"`
	Packages          json.RawMessage   `json:"Packages,omitempty"`
	Misconfigurations json.RawMessage   `json:"Misconfigurations,omitempty"`
	Secrets           json.RawMessage   `json:"Secrets,omitempty"`
	Licenses          json.RawMessage   `json:"Licenses,omitempty"`
}

// Vulnerability represents a single vulnerability finding. Fields the plugin
// inspects are typed; all other JSON fields are captured in Extras and
// re-emitted on marshal to avoid data loss.
type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion,omitempty"`
	Severity         string          `json:"Severity"`
	CVSS             json.RawMessage `json:"CVSS,omitempty"`
	VulnPrio         *VulnPrio       `json:"VulnPrio,omitempty"`
	// Extras holds all other JSON fields for passthrough.
	Extras map[string]json.RawMessage `json:"-"`
}

// vulnKnownFields lists the JSON keys that correspond to typed fields on
// Vulnerability. Everything else goes into Extras.
var vulnKnownFields = map[string]bool{
	"VulnerabilityID":  true,
	"PkgName":          true,
	"InstalledVersion": true,
	"FixedVersion":     true,
	"Severity":         true,
	"CVSS":             true,
	"VulnPrio":         true,
}

// UnmarshalJSON decodes a Vulnerability from JSON, extracting known fields
// into their typed counterparts and capturing everything else in Extras.
func (v *Vulnerability) UnmarshalJSON(data []byte) error {
	// Decode all fields into a generic map.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	// Helper to unmarshal a specific key into a destination.
	get := func(key string, dst interface{}) error {
		raw, ok := all[key]
		if !ok {
			return nil
		}
		return json.Unmarshal(raw, dst)
	}

	if err := get("VulnerabilityID", &v.VulnerabilityID); err != nil {
		return err
	}
	if err := get("PkgName", &v.PkgName); err != nil {
		return err
	}
	if err := get("InstalledVersion", &v.InstalledVersion); err != nil {
		return err
	}
	if err := get("FixedVersion", &v.FixedVersion); err != nil {
		return err
	}
	if err := get("Severity", &v.Severity); err != nil {
		return err
	}

	if raw, ok := all["CVSS"]; ok {
		v.CVSS = raw
	}

	if _, ok := all["VulnPrio"]; ok {
		v.VulnPrio = &VulnPrio{}
		if err := get("VulnPrio", v.VulnPrio); err != nil {
			return err
		}
	}

	// Capture unknown fields.
	extras := make(map[string]json.RawMessage)
	for k, val := range all {
		if !vulnKnownFields[k] {
			extras[k] = val
		}
	}
	if len(extras) > 0 {
		v.Extras = extras
	}

	return nil
}

// MarshalJSON encodes a Vulnerability to JSON, merging typed fields with
// the passthrough Extras map.
func (v Vulnerability) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	// Merge extras first so typed fields take precedence.
	for k, val := range v.Extras {
		m[k] = val
	}

	m["VulnerabilityID"] = v.VulnerabilityID
	m["PkgName"] = v.PkgName
	m["InstalledVersion"] = v.InstalledVersion
	if v.FixedVersion != "" {
		m["FixedVersion"] = v.FixedVersion
	}
	m["Severity"] = v.Severity
	if v.CVSS != nil {
		m["CVSS"] = v.CVSS
	}
	if v.VulnPrio != nil {
		m["VulnPrio"] = v.VulnPrio
	}

	return json.Marshal(m)
}
