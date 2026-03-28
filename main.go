// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package main

import (
	"os"

	"github.com/steadybit/dns-inject/cmd"
)

var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	v := version
	if commit != "unknown" {
		v += " (" + commit + ")"
	}
	if err := cmd.NewRootCmd(v).Execute(); err != nil {
		os.Exit(1)
	}
}
