// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/bonial-oss/trivy-plugin-vuln-prio/cmd"
)

func main() {
	if err := cmd.NewRootCommand().Execute(); err != nil {
		var exitErr *cmd.ExitError
		if errors.As(err, &exitErr) {
			if exitErr.Message != "" {
				fmt.Fprintf(os.Stderr, "Error: %s\n", exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
}
