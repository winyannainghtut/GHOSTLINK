// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package hostfw

import (
	"strings"
	"testing"
)

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

// Only the filter FORWARD jumps marked Docker get a copy in DOCKER-USER: that chain sees forwarded
// traffic only, ahead of Docker's accept rules. The others (the IPsec component's, whose chain
// counts speed limits) are left alone.
func TestDockerCopies(t *testing.T) {
	jumps := []Jump{
		{Table: "filter", Chain: "INPUT", Match: []string{"-i", "glmesh0"}, Target: "IN"},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-i", "glmesh0"}, Target: "FWD", Docker: true},
		{Table: "filter", Chain: "FORWARD", Match: []string{"-o", "glmesh0"}, Target: "OUT", Docker: true},
		{Table: "filter", Chain: "FORWARD", Target: "OTHER"},
		{Table: "mangle", Chain: "FORWARD", Target: "MSS"},
	}
	copies := dockerCopies(jumps)
	if len(copies) != 2 || copies[0].Chain != dockerChain || copies[0].Target != "FWD" || copies[1].Target != "OUT" ||
		strings.Join(copies[1].args("-I", "1"), " ") != "-t filter -I DOCKER-USER 1 -o glmesh0 -j OUT" {
		t.Fatalf("copies: %+v", copies)
	}
	if jumps[1].Chain != "FORWARD" {
		t.Fatal("dockerCopies changed the jumps it was given")
	}
}
