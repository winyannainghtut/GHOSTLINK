// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package main

import "testing"

// GHOSTLINK_RUN_AS names an account other than root, as UID:GID.
func TestParseRunAs(t *testing.T) {
	if uid, gid, err := parseRunAs(" 999:998 "); err != nil || uid != 999 || gid != 998 {
		t.Fatalf("999:998: %d:%d %v", uid, gid, err)
	}
	for _, spec := range []string{"", "999", "0:998", "999:0", "0:0", "-1:5", "a:b", "999:998:1", "99999999999:1", "999: 998"} {
		if _, _, err := parseRunAs(spec); err == nil {
			t.Errorf("%q should be refused", spec)
		}
	}
}
