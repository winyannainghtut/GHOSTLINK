// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !(linux && (amd64 || arm64))

package main

import (
	"fmt"
	"os"
)

// becomeAccount: only the server's own platforms, Linux on amd64 and arm64, can start as root and
// become another account (see account_linux.go). Elsewhere a server told to refuses to start.
func becomeAccount() error {
	if spec, named := os.LookupEnv(runAsVariable); named {
		return fmt.Errorf("%s=%s works only on Linux (amd64, arm64)", runAsVariable, spec)
	}
	return nil
}
