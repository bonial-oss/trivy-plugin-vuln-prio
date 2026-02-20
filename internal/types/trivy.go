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

// Result represents a single Trivy scan result for a target. Fields the
// plugin inspects are typed; all other JSON fields are captured in Extras
// and re-emitted on marshal to avoid data loss.
type Result struct {
	Target                       string            `json:"Target"`
	Class                        string            `json:"Class,omitempty"`
	Type                         string            `json:"Type,omitempty"`
	Vulnerabilities              []Vulnerability   `json:"Vulnerabilities,omitempty"`
	ExperimentalModifiedFindings []ModifiedFinding `json:"ExperimentalModifiedFindings,omitempty"`
	Packages                     json.RawMessage   `json:"Packages,omitempty"`
	Misconfigurations            json.RawMessage   `json:"Misconfigurations,omitempty"`
	Secrets                      json.RawMessage   `json:"Secrets,omitempty"`
	Licenses                     json.RawMessage   `json:"Licenses,omitempty"`
	// Extras holds all other JSON fields for passthrough.
	Extras map[string]json.RawMessage `json:"-"`
}

// resultKnownFields lists the JSON keys that correspond to typed fields on
// Result. Everything else goes into Extras.
var resultKnownFields = map[string]bool{
	"Target":                       true,
	"Class":                        true,
	"Type":                         true,
	"Vulnerabilities":              true,
	"ExperimentalModifiedFindings": true,
	"Packages":                     true,
	"Misconfigurations":            true,
	"Secrets":                      true,
	"Licenses":                     true,
}

// UnmarshalJSON decodes a Result from JSON, extracting known fields into
// their typed counterparts and capturing everything else in Extras.
func (r *Result) UnmarshalJSON(data []byte) error {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	get := func(key string, dst interface{}) error {
		raw, ok := all[key]
		if !ok {
			return nil
		}
		return json.Unmarshal(raw, dst)
	}

	if err := get("Target", &r.Target); err != nil {
		return err
	}
	if err := get("Class", &r.Class); err != nil {
		return err
	}
	if err := get("Type", &r.Type); err != nil {
		return err
	}
	if err := get("Vulnerabilities", &r.Vulnerabilities); err != nil {
		return err
	}
	if err := get("ExperimentalModifiedFindings", &r.ExperimentalModifiedFindings); err != nil {
		return err
	}

	if raw, ok := all["Packages"]; ok {
		r.Packages = raw
	}
	if raw, ok := all["Misconfigurations"]; ok {
		r.Misconfigurations = raw
	}
	if raw, ok := all["Secrets"]; ok {
		r.Secrets = raw
	}
	if raw, ok := all["Licenses"]; ok {
		r.Licenses = raw
	}

	extras := make(map[string]json.RawMessage)
	for k, val := range all {
		if !resultKnownFields[k] {
			extras[k] = val
		}
	}
	if len(extras) > 0 {
		r.Extras = extras
	}

	return nil
}

// MarshalJSON encodes a Result to JSON, merging typed fields with the
// passthrough Extras map.
func (r Result) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	for k, val := range r.Extras {
		m[k] = val
	}

	m["Target"] = r.Target
	if r.Class != "" {
		m["Class"] = r.Class
	}
	if r.Type != "" {
		m["Type"] = r.Type
	}
	if len(r.Vulnerabilities) > 0 {
		m["Vulnerabilities"] = r.Vulnerabilities
	}
	if len(r.ExperimentalModifiedFindings) > 0 {
		m["ExperimentalModifiedFindings"] = r.ExperimentalModifiedFindings
	}
	if r.Packages != nil {
		m["Packages"] = r.Packages
	}
	if r.Misconfigurations != nil {
		m["Misconfigurations"] = r.Misconfigurations
	}
	if r.Secrets != nil {
		m["Secrets"] = r.Secrets
	}
	if r.Licenses != nil {
		m["Licenses"] = r.Licenses
	}

	return json.Marshal(m)
}

// ModifiedFinding represents a suppressed or modified vulnerability finding
// from Trivy's --show-suppressed output.
type ModifiedFinding struct {
	Type      string        `json:"Type"`
	Status    string        `json:"Status"`
	Statement string        `json:"Statement,omitempty"`
	Source    string        `json:"Source,omitempty"`
	Finding   Vulnerability `json:"Finding"`
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
