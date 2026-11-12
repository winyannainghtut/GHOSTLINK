// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package asn finds the autonomous system (AS) and its operator behind an IP address, from the
// public ip2asn data (https://iptoasn.com, Public Domain Dedication and License 1.0): a tab
// separated list of address ranges, each with the number and the name of the AS that announces it.
//
// The data comes from a third party and is not trusted: the parser limits what it reads, ignores
// lines it cannot read (and refuses a file where too many are unreadable), and cleans the names
// before they are shown, because they end up in terminals and web pages.
package asn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Info is the AS an address belongs to.
type Info struct {
	// Number is the AS number, such as 64500 for "AS64500".
	Number uint32
	// Operator is the name of the organization that runs it, as the registries give it.
	Operator string
}

// String reads like "AS64500 Example Telecom".
func (i Info) String() string {
	if i.Operator == "" {
		return "AS" + strconv.FormatUint(uint64(i.Number), 10)
	}
	return "AS" + strconv.FormatUint(uint64(i.Number), 10) + " " + i.Operator
}

type range4 struct{ start, end, number uint32 }

type range6 struct {
	start, end [2]uint64
	number     uint32
}

type name struct {
	number uint32
	text   string
}

// Table maps address ranges to autonomous systems. It is read only once built, so any number of
// goroutines may look addresses up in it.
type Table struct {
	v4    []range4
	v6    []range6
	names []name // sorted by number
}

// Limits of what Parse accepts.
const (
	// MaxLine is the longest line read; a longer one is not a line of this format.
	MaxLine = 4096
	// MaxRanges bounds the memory a file can take (the real file has about 720,000).
	MaxRanges = 2_000_000
	// maxOperator is the longest operator name kept, in characters.
	maxOperator = 60
	// unreadableShare is the share of lines that may be unreadable before the file is refused:
	// a few odd lines in a large file are normal, a different format is not.
	unreadableShare = 100 // one in a hundred
)

// ErrNotIP2ASN is returned for data that is not in the ip2asn format.
var ErrNotIP2ASN = errors.New("the data is not in the ip2asn format")

// Parse reads ip2asn data: lines of "range_start, range_end, AS number, country, description"
// separated by tabs. Ranges of AS 0 (not announced by anyone) are left out. The caller limits how
// much of r is read.
func Parse(r io.Reader) (*Table, error) {
	t := &Table{}
	names := map[uint32]string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024), MaxLine)
	var lines, unreadable int
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		lines++
		fields := bytes.SplitN(line, []byte{'\t'}, 5)
		if len(fields) < 5 {
			unreadable++
			continue
		}
		start, errStart := netip.ParseAddr(string(fields[0]))
		end, errEnd := netip.ParseAddr(string(fields[1]))
		number, errNumber := strconv.ParseUint(string(fields[2]), 10, 32)
		if errStart != nil || errEnd != nil || errNumber != nil {
			unreadable++
			continue
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Is4() != end.Is4() || end.Less(start) || start.Is4In6() {
			unreadable++
			continue
		}
		if number == 0 {
			continue // not routed
		}
		if len(t.v4)+len(t.v6) >= MaxRanges {
			return nil, fmt.Errorf("%w: more than %d ranges", ErrNotIP2ASN, MaxRanges)
		}
		if start.Is4() {
			a, b := start.As4(), end.As4()
			t.v4 = append(t.v4, range4{be32(a[:]), be32(b[:]), uint32(number)})
		} else {
			a, b := start.As16(), end.As16()
			t.v6 = append(t.v6, range6{[2]uint64{be64(a[:8]), be64(a[8:])}, [2]uint64{be64(b[:8]), be64(b[8:])}, uint32(number)})
		}
		if _, known := names[uint32(number)]; !known {
			names[uint32(number)] = operatorOf(string(fields[4]))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotIP2ASN, err)
	}
	if lines == 0 || unreadable*unreadableShare > lines {
		return nil, fmt.Errorf("%w: %d of %d lines could not be read", ErrNotIP2ASN, unreadable, lines)
	}
	sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].start < t.v4[j].start })
	sort.Slice(t.v6, func(i, j int) bool { return less128(t.v6[i].start, t.v6[j].start) })
	t.names = make([]name, 0, len(names))
	for number, text := range names {
		t.names = append(t.names, name{number, text})
	}
	sort.Slice(t.names, func(i, j int) bool { return t.names[i].number < t.names[j].number })
	return t, nil
}

// Len is the number of ranges in the table.
func (t *Table) Len() int {
	if t == nil {
		return 0
	}
	return len(t.v4) + len(t.v6)
}

// Lookup finds the AS an address belongs to. Addresses nobody announces (private, loopback,
// reserved, or not routed) are not found.
func (t *Table) Lookup(addr netip.Addr) (Info, bool) {
	if t == nil || !addr.IsValid() {
		return Info{}, false
	}
	addr = addr.Unmap().WithZone("")
	var number uint32
	if addr.Is4() {
		b := addr.As4()
		a := be32(b[:])
		i := sort.Search(len(t.v4), func(i int) bool { return t.v4[i].start > a }) - 1
		if i < 0 || a > t.v4[i].end {
			return Info{}, false
		}
		number = t.v4[i].number
	} else {
		b := addr.As16()
		a := [2]uint64{be64(b[:8]), be64(b[8:])}
		i := sort.Search(len(t.v6), func(i int) bool { return less128(a, t.v6[i].start) }) - 1
		if i < 0 || less128(t.v6[i].end, a) {
			return Info{}, false
		}
		number = t.v6[i].number
	}
	info := Info{Number: number}
	if i := sort.Search(len(t.names), func(i int) bool { return t.names[i].number >= number }); i < len(t.names) && t.names[i].number == number {
		info.Operator = t.names[i].text
	}
	return info, true
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func be64(b []byte) uint64 {
	return uint64(be32(b[:4]))<<32 | uint64(be32(b[4:]))
}

func less128(a, b [2]uint64) bool { return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1]) }

// operatorOf turns a registry description such as "CLOUDFLARENET - Cloudflare, Inc." into the
// organization's name. The part before " - " is the AS handle; a description without one is the
// name. The text is cleaned: it comes from a file we do not control and is shown in terminals and
// web pages.
func operatorOf(description string) string {
	if _, after, found := strings.Cut(description, " - "); found && strings.TrimSpace(after) != "" {
		description = after
	}
	var b strings.Builder
	count, space := 0, false
	for _, r := range description {
		switch {
		case r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r):
			// Control characters (an escape sequence starts with one), invisible formatting
			// (right-to-left overrides) and undecodable bytes have no place in a name.
			space = true
		case unicode.IsSpace(r):
			space = true
		default:
			if count == maxOperator {
				// One more character than fits: keep room for the ellipsis.
				return strings.TrimSpace(string([]rune(b.String())[:maxOperator-1])) + "…"
			}
			if space && b.Len() > 0 {
				b.WriteByte(' ')
				count++
			}
			space = false
			b.WriteRune(r)
			count++
		}
	}
	return b.String()
}
