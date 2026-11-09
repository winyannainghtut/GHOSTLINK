// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// runAsVariable names the account the server becomes when it starts as root: "UID:GID".
const runAsVariable = "GHOSTLINK_RUN_AS"

// parseRunAs reads "UID:GID". Neither may be 0: the point is to stop being root.
func parseRunAs(spec string) (uid, gid int, err error) {
	user, group, ok := strings.Cut(strings.TrimSpace(spec), ":")
	if ok {
		uid, err = strconv.Atoi(user)
		if err == nil {
			gid, err = strconv.Atoi(group)
		}
	}
	if !ok || err != nil || uid <= 0 || gid <= 0 || uid > 1<<31-2 || gid > 1<<31-2 {
		return 0, 0, fmt.Errorf("%s must be UID:GID of an account other than root, not %q", runAsVariable, spec)
	}
	return uid, gid, nil
}
