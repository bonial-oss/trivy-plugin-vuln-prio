// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package types

import "encoding/json"

// SARIFReport represents a minimal SARIF v2.1.0 report.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single SARIF run. The Tool field is preserved as
// raw JSON. Extra fields are captured in Extras for passthrough.
type SARIFRun struct {
	Tool    json.RawMessage            `json:"tool"`
	Results []SARIFResult              `json:"results"`
	Extras  map[string]json.RawMessage `json:"-"`
}

// sarifRunKnownFields lists the JSON keys that correspond to typed fields
// on SARIFRun.
var sarifRunKnownFields = map[string]bool{
	"tool":    true,
	"results": true,
}

// UnmarshalJSON decodes a SARIFRun from JSON, extracting known fields and
// capturing the rest in Extras.
func (r *SARIFRun) UnmarshalJSON(data []byte) error {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	if raw, ok := all["tool"]; ok {
		r.Tool = raw
	}

	if raw, ok := all["results"]; ok {
		if err := json.Unmarshal(raw, &r.Results); err != nil {
			return err
		}
	}

	extras := make(map[string]json.RawMessage)
	for k, val := range all {
		if !sarifRunKnownFields[k] {
			extras[k] = val
		}
	}
	if len(extras) > 0 {
		r.Extras = extras
	}

	return nil
}

// MarshalJSON encodes a SARIFRun to JSON, merging typed fields with the
// passthrough Extras map.
func (r SARIFRun) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	for k, val := range r.Extras {
		m[k] = val
	}

	// tool and results are required SARIF fields; always emit them.
	if r.Tool != nil {
		m["tool"] = r.Tool
	} else {
		m["tool"] = json.RawMessage(`{}`)
	}
	if r.Results != nil {
		m["results"] = r.Results
	} else {
		m["results"] = []SARIFResult{}
	}

	return json.Marshal(m)
}

// SARIFResult represents a single result within a SARIF run. Extra fields
// are captured in Extras for passthrough.
type SARIFResult struct {
	RuleID     string                     `json:"ruleId"`
	Level      string                     `json:"level"`
	Message    json.RawMessage            `json:"message"`
	Properties map[string]json.RawMessage `json:"properties,omitempty"`
	Extras     map[string]json.RawMessage `json:"-"`
}

// sarifResultKnownFields lists the JSON keys that correspond to typed fields
// on SARIFResult.
var sarifResultKnownFields = map[string]bool{
	"ruleId":     true,
	"level":      true,
	"message":    true,
	"properties": true,
}

// UnmarshalJSON decodes a SARIFResult from JSON, extracting known fields and
// capturing the rest in Extras.
func (r *SARIFResult) UnmarshalJSON(data []byte) error {
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

	if err := get("ruleId", &r.RuleID); err != nil {
		return err
	}
	if err := get("level", &r.Level); err != nil {
		return err
	}
	if raw, ok := all["message"]; ok {
		r.Message = raw
	}
	if _, ok := all["properties"]; ok {
		r.Properties = make(map[string]json.RawMessage)
		if err := get("properties", &r.Properties); err != nil {
			return err
		}
	}

	extras := make(map[string]json.RawMessage)
	for k, val := range all {
		if !sarifResultKnownFields[k] {
			extras[k] = val
		}
	}
	if len(extras) > 0 {
		r.Extras = extras
	}

	return nil
}

// MarshalJSON encodes a SARIFResult to JSON, merging typed fields with the
// passthrough Extras map.
func (r SARIFResult) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	for k, val := range r.Extras {
		m[k] = val
	}

	if r.RuleID != "" {
		m["ruleId"] = r.RuleID
	}
	if r.Level != "" {
		m["level"] = r.Level
	}
	if r.Message != nil {
		m["message"] = r.Message
	}
	if len(r.Properties) > 0 {
		m["properties"] = r.Properties
	}

	return json.Marshal(m)
}
