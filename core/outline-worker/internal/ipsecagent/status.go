// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package ipsecagent

import (
	"strconv"
	"strings"

	"github.com/strongswan/govici/vici"

	"ghostlink.local/outline-worker/internal/ipsecproto"
)

func field(m *vici.Message, key string) string {
	if v, ok := m.Get(key).(string); ok {
		return v
	}
	return ""
}

func number(m *vici.Message, key string) uint64 {
	n, _ := strconv.ParseUint(field(m, key), 10, 64)
	return n
}

// identityOf is who authenticated: the EAP or XAuth user when there is one (an IPsec PSK's IKE
// identity is the shared group name), else the IKE identity from the certificate.
func identityOf(m *vici.Message) string {
	for _, key := range []string{"remote-eap-id", "remote-xauth-id", "remote-id"} {
		if id := field(m, key); id != "" {
			return id
		}
	}
	return ""
}

// ParseSAs reads list-sa events into the status the server understands. Only established SAs
// are reported.
func ParseSAs(events []*vici.Message) []ipsecproto.SA {
	sas := []ipsecproto.SA{}
	for _, event := range events {
		for _, name := range event.Keys() {
			m, ok := event.Get(name).(*vici.Message)
			if !ok || field(m, "uniqueid") == "" || field(m, "state") != "ESTABLISHED" {
				continue
			}
			version, _ := strconv.Atoi(field(m, "version"))
			sa := ipsecproto.SA{
				Name: name, UniqueID: field(m, "uniqueid"), Version: version, Identity: identityOf(m),
				Remote: field(m, "remote-host"), Established: int64(number(m, "established")),
				Children: []ipsecproto.Child{},
			}
			if vips, ok := m.Get("remote-vips").([]string); ok && len(vips) > 0 {
				sa.VirtualIP = vips[0]
			}
			if children, ok := m.Get("child-sas").(*vici.Message); ok {
				for _, key := range children.Keys() {
					c, ok := children.Get(key).(*vici.Message)
					if !ok {
						continue
					}
					sa.Children = append(sa.Children, ipsecproto.Child{
						UniqueID: field(c, "uniqueid"), BytesIn: number(c, "bytes-in"), BytesOut: number(c, "bytes-out"),
					})
				}
			}
			sas = append(sas, sa)
		}
	}
	return sas
}

// Disallowed lists established SAs that must end: their identity is no longer allowed (removed
// key, disabled or over-limit user) or their connection was unloaded.
func Disallowed(sas []ipsecproto.SA, allowed map[string]bool, conns map[string]bool) []string {
	var ids []string
	for _, sa := range sas {
		if !conns[sa.Name] || !allowed[strings.ToLower(sa.Identity)] {
			ids = append(ids, sa.UniqueID)
		}
	}
	return ids
}
