// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

//go:build !linux

package ipsecagent

import "errors"

var errLinuxOnly = errors.New("the IPsec agent runs on Linux only")

func createInterface() (bool, error)   { return false, errLinuxOnly }
func addGateway(bool, string) error    { return errLinuxOnly }
func removeGateway(bool, string) error { return errLinuxOnly }
func deleteInterface() error           { return nil }
