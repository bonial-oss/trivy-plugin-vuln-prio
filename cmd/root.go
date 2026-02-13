// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/epss"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/datasource/kev"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/enricher"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/input"
	"github.com/bonial-oss/trivy-plugin-vuln-prio/internal/output"
)

// Version is set at build time via ldflags.
var Version = "dev"

// ExitError signals a non-zero exit code with an optional message.
type ExitError struct {
	Code    int
	Message string
}

func (e *ExitError) Error() string { return e.Message }

// Options holds all CLI flag values.
type Options struct {
	NoEPSS              bool
	NoKEV               bool
	Format              string
	Output              string
	EPSSThreshold       float64
	KEVOnly             bool
	FailOnKEV           bool
	FailOnEPSSThreshold float64
	SortBy              string
	SkipDBUpdate        bool
	CacheDir            string
}

// NewRootCommand creates the root cobra command with all flags.
func NewRootCommand() *cobra.Command {
	opts := &Options{}

	cmd := &cobra.Command{
		Use:     "vuln-prio",
		Short:   "Enrich Trivy vulnerability reports with EPSS scores, KEV status, and risk ratings",
		Version: Version,
		Long: `vuln-prio is a Trivy plugin that reads a Trivy JSON or SARIF report from
stdin and enriches each vulnerability with EPSS probability scores, CISA
Known Exploited Vulnerabilities (KEV) status, and a composite risk score.

Usage:
  trivy image -f json alpine:latest | trivy vuln-prio
  trivy image -f sarif alpine:latest | trivy vuln-prio --format sarif`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return run(opts)
		},
	}

	flags := cmd.Flags()
	flags.BoolVar(&opts.NoEPSS, "no-epss", false, "Disable EPSS enrichment")
	flags.BoolVar(&opts.NoKEV, "no-kev", false, "Disable KEV enrichment")
	flags.StringVar(&opts.Format, "format", "json", "Output format: json, table, sarif")
	flags.StringVarP(&opts.Output, "output", "o", "", "Write to file instead of stdout")
	flags.Float64Var(&opts.EPSSThreshold, "epss-threshold", 0, "Only show vulns with EPSS score >= value")
	flags.BoolVar(&opts.KEVOnly, "kev-only", false, "Only show vulns present in KEV")
	flags.BoolVar(&opts.FailOnKEV, "fail-on-kev", false, "Exit code 1 if any KEV vuln found")
	flags.Float64Var(&opts.FailOnEPSSThreshold, "fail-on-epss-threshold", 0, "Exit code 1 if any vuln has EPSS >= value")
	flags.StringVar(&opts.SortBy, "sort-by", "risk", "Sort table by: risk, epss, severity, cve")
	flags.BoolVar(&opts.SkipDBUpdate, "skip-db-update", false, "Use cached data without update check")
	flags.StringVar(&opts.CacheDir, "cache-dir", "", "Override cache directory")

	return cmd
}

// run orchestrates the full enrichment pipeline.
func run(opts *Options) error {
	// Read all of stdin.
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading stdin: %w", err)
	}
	if len(data) == 0 {
		return &ExitError{Code: 2, Message: "no input provided on stdin"}
	}

	// Detect input format.
	parsed, err := input.Parse(data)
	if err != nil {
		return fmt.Errorf("parsing input: %w", err)
	}

	// Validate format compatibility.
	if parsed.Format == input.FormatSARIF && opts.Format != "sarif" {
		return &ExitError{
			Code:    3,
			Message: "SARIF input requires --format sarif",
		}
	}
	if parsed.Format == input.FormatJSON && opts.Format == "sarif" {
		return &ExitError{
			Code:    3,
			Message: "Trivy JSON input is not compatible with --format sarif",
		}
	}

	// Determine cache directory.
	cacheDir := opts.CacheDir
	if cacheDir == "" {
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			cacheDir = filepath.Join(xdg, ".trivy", "plugins", "vuln-prio")
		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("determining home directory: %w", err)
			}
			cacheDir = filepath.Join(home, ".trivy", "plugins", "vuln-prio")
		}
	}

	// Initialize data sources.
	var epssSource *epss.Source
	var kevSource *kev.Source

	if !opts.NoEPSS {
		epssSource = epss.NewSource(cacheDir)
	}
	if !opts.NoKEV {
		kevSource = kev.NewSource(cacheDir)
	}

	// Load data sources.
	if epssSource != nil {
		if err := epssSource.Load(opts.SkipDBUpdate); err != nil {
			return fmt.Errorf("loading EPSS data: %w", err)
		}
	}
	if kevSource != nil {
		if err := kevSource.Load(opts.SkipDBUpdate); err != nil {
			return fmt.Errorf("loading KEV data: %w", err)
		}
	}

	// Build enricher.
	e := enricher.New(epssSource, kevSource)
	cfg := enricher.Config{
		EPSSThreshold:       opts.EPSSThreshold,
		KEVOnly:             opts.KEVOnly,
		FailOnKEV:           opts.FailOnKEV,
		FailOnEPSSThreshold: opts.FailOnEPSSThreshold,
	}

	// Determine output writer.
	var w io.Writer
	if opts.Output != "" && opts.Output != "-" {
		f, err := os.Create(opts.Output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		w = f
	} else {
		w = os.Stdout
	}

	var policyViolation bool
	switch parsed.Format {
	case input.FormatJSON:
		result, err := e.Enrich(parsed.TrivyReport, cfg)
		if err != nil {
			return fmt.Errorf("enriching report: %w", err)
		}
		policyViolation = result.PolicyViolation

		// Write output.
		switch opts.Format {
		case "json":
			if err := output.WriteJSON(w, result.Report); err != nil {
				return err
			}
		case "table":
			tableCfg := output.TableConfig{
				ShowEPSS: !opts.NoEPSS,
				ShowKEV:  !opts.NoKEV,
				ShowRisk: !opts.NoEPSS && !opts.NoKEV,
				SortBy:   opts.SortBy,
			}
			if err := output.WriteTable(w, result.Report, tableCfg); err != nil {
				return err
			}
		default:
			return &ExitError{
				Code:    2,
				Message: fmt.Sprintf("unsupported output format: %s", opts.Format),
			}
		}

	case input.FormatSARIF:
		sarifResult, err := e.EnrichSARIF(parsed.SARIFReport, cfg)
		if err != nil {
			return fmt.Errorf("enriching SARIF report: %w", err)
		}
		policyViolation = sarifResult.PolicyViolation

		if err := output.WriteJSON(w, sarifResult.Report); err != nil {
			return err
		}
	}

	// Check policy violation.
	if policyViolation {
		return &ExitError{Code: 1, Message: "policy violation detected"}
	}

	return nil
}
