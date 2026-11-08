// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package hostfw

import "testing"

// An agent on the host follows the backend the host's iptables command uses, which Docker uses
// too, so it is right even at boot before anyone added rules.
func TestBackendOf(t *testing.T) {
	for version, want := range map[string]string{
		"iptables v1.8.7 (nf_tables)\n": "nft",
		"iptables v1.8.4 (legacy)\n":    "legacy",
		"iptables v1.6.1\n":             "",
		"":                              "",
	} {
		if got := backendOf(version); got != want {
			t.Errorf("%q: %q, want %q", version, got, want)
		}
	}
}
