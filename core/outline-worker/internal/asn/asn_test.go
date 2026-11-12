// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package asn

import (
	"compress/gzip"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The ranges and AS numbers are the ones set aside for documentation (RFC 5737, RFC 3849 and
// RFC 5398): no real network is named here.
const sample = `192.0.2.0	192.0.2.255	64496	ZZ	EXAMPLE-ONE - Example Telecom One, Inc.
198.51.100.0	198.51.100.127	64497	ZZ	EXAMPLE-TWO - Example Mobile Two
198.51.100.128	198.51.100.255	64498	ZZ	NOHANDLE
203.0.113.0	203.0.113.255	0	None	Not routed
203.0.114.0	203.0.114.9	64499	ZZ	EXAMPLE-FIVE - Example Five
2001:db8::	2001:db8:ffff:ffff:ffff:ffff:ffff:ffff	64496	ZZ	EXAMPLE-ONE - Example Telecom One, Inc.
2001:db9::	2001:db9::ffff	64497	ZZ	EXAMPLE-TWO - Example Mobile Two
`

func parse(t *testing.T, text string) *Table {
	t.Helper()
	table, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestLookupFindsTheRangeAnAddressIsIn(t *testing.T) {
	table := parse(t, sample)
	if table.Len() != 6 {
		t.Fatalf("%d ranges, want 6 (the not-routed one is left out)", table.Len())
	}
	for address, want := range map[string]Info{
		"192.0.2.0":                              {64496, "Example Telecom One, Inc."}, // first address of a range
		"192.0.2.255":                            {64496, "Example Telecom One, Inc."}, // last address
		"192.0.2.77":                             {64496, "Example Telecom One, Inc."},
		"198.51.100.127":                         {64497, "Example Mobile Two"},
		"198.51.100.128":                         {64498, "NOHANDLE"}, // a description without a handle is the name
		"203.0.114.9":                            {64499, "Example Five"},
		"2001:db8::1":                            {64496, "Example Telecom One, Inc."},
		"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff": {64496, "Example Telecom One, Inc."},
		"2001:db9::abcd":                         {64497, "Example Mobile Two"},
		"::ffff:192.0.2.9":                       {64496, "Example Telecom One, Inc."}, // an IPv4 address written as IPv6
		"fe80::1%eth0":                           {},                                   // zone is ignored, link-local is nobody's
	} {
		got, found := table.Lookup(netip.MustParseAddr(address))
		if want == (Info{}) {
			if found {
				t.Errorf("%s: found %+v, want nothing", address, got)
			}
			continue
		}
		if !found || got != want {
			t.Errorf("%s: %+v (found %v), want %+v", address, got, found, want)
		}
	}
	for _, address := range []string{
		"192.0.1.255",                         // just before a range
		"192.0.3.0",                           // just after it
		"203.0.113.50",                        // not routed (AS 0)
		"203.0.114.10",                        // just after the last range
		"10.1.2.3", "127.0.0.1", "100.64.0.1", // private, loopback, shared address space
		"1.1.1.1", "255.255.255.255", "0.0.0.0", // before the first range and after the last
		"::1", "2001:db7::", "2001:db9::1:0", // outside the IPv6 ranges
	} {
		if info, found := table.Lookup(netip.MustParseAddr(address)); found {
			t.Errorf("%s: found %+v, want nothing", address, info)
		}
	}
	if _, found := table.Lookup(netip.Addr{}); found {
		t.Error("an invalid address was found")
	}
	var empty *Table
	if _, found := empty.Lookup(netip.MustParseAddr("192.0.2.1")); found || empty.Len() != 0 {
		t.Error("a missing table found something")
	}
}

func TestInfoString(t *testing.T) {
	if got := (Info{64496, "Example Telecom"}).String(); got != "AS64496 Example Telecom" {
		t.Fatal(got)
	}
	if got := (Info{64496, ""}).String(); got != "AS64496" {
		t.Fatal(got)
	}
}

// Names come from a file we do not control and are shown in terminals and web pages.
func TestOperatorNamesAreCleaned(t *testing.T) {
	long := strings.Repeat("Longname ", 20)
	for description, want := range map[string]string{
		"HANDLE - Example Telecom": "Example Telecom",
		"HANDLE - ":                "HANDLE -",
		"JUSTANAME":                "JUSTANAME",
		"A - B - C":                "B - C",
		"  Spaced   out \t name  ": "Spaced out name",
		"H - Esc\x1b[31mape\x1b]0;title\x07 done":    "Esc [31mape ]0;title done",
		"H - Bell\x07 and\x00nul\r\nlines":           "Bell and nul lines",
		"H - right‮to-left​zero":                     "right to-left zero",
		"H - bad \xff\xfe bytes":                     "bad bytes",
		"H - Orange Myanmar — ဗမာ":                   "Orange Myanmar — ဗမာ",
		"H - " + long:                                strings.TrimSpace(strings.Repeat("Longname ", 20))[:59] + "…",
		"H - networkdescr: YangZhou , Jiangsu China": "networkdescr: YangZhou , Jiangsu China",
	} {
		got := operatorOf(description)
		if got != want {
			t.Errorf("operatorOf(%q) = %q, want %q", description, got, want)
		}
		for _, r := range got {
			if r < ' ' || r == 0x7f {
				t.Errorf("operatorOf(%q) kept a control character: %q", description, got)
			}
		}
	}
	if n := len([]rune(operatorOf("H - " + strings.Repeat("é", 500)))); n > maxOperator+1 {
		t.Errorf("a name of %d characters was kept", n)
	}
}

func TestParseRefusesWhatIsNotIP2ASN(t *testing.T) {
	for name, text := range map[string]string{
		"empty":     "",
		"comments":  "# nothing here\n",
		"html":      "<html><body>429 Too many requests</body></html>\n",
		"csv":       "192.0.2.0,192.0.2.255,64496,ZZ,Example\n",
		"too short": "192.0.2.0\t192.0.2.255\t64496\n",
		"bad IPs":   "not\tan\t64496\tZZ\taddress\n",
	} {
		if _, err := Parse(strings.NewReader(text)); !errors.Is(err, ErrNotIP2ASN) {
			t.Errorf("%s: err = %v, want ErrNotIP2ASN", name, err)
		}
	}
	// A line longer than the limit is not a line of this format.
	if _, err := Parse(strings.NewReader("192.0.2.0\t192.0.2.255\t64496\tZZ\t" + strings.Repeat("x", MaxLine) + "\n")); !errors.Is(err, ErrNotIP2ASN) {
		t.Errorf("a very long line: %v", err)
	}
}

// A few odd lines in a big file are normal; the rest is still used.
func TestParseToleratesAFewUnreadableLines(t *testing.T) {
	text := strings.Repeat(sample, 100) + "garbage line\n192.0.2.9\t192.0.2.1\t64500\tZZ\tend before start\n\n# comment\n198.51.100.1\t2001:db8::1\t64500\tZZ\tmixed families\n"
	table, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if _, found := table.Lookup(netip.MustParseAddr("192.0.2.9")); !found {
		t.Fatal("the readable lines were not used")
	}
}

func TestParseKeepsTheMemoryBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxRanges+10; i++ {
		b.WriteString("192.0.2.0\t192.0.2.255\t64496\tZZ\tX - Y\n")
	}
	if _, err := Parse(strings.NewReader(b.String())); !errors.Is(err, ErrNotIP2ASN) {
		t.Fatalf("a file of %d ranges: %v", MaxRanges+10, err)
	}
}

// With the real file (GHOSTLINK_TEST_ASN_FILE, a .tsv or .tsv.gz of iptoasn.com's combined data),
// the parser reads all of it quickly and the table stays small. Skipped without the file.
func TestRealDataSize(t *testing.T) {
	path := os.Getenv("GHOSTLINK_TEST_ASN_FILE")
	if path == "" {
		t.Skip("GHOSTLINK_TEST_ASN_FILE is not set")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	reader := interface {
		Read([]byte) (int, error)
	}(file)
	if strings.HasSuffix(path, ".gz") {
		if reader, err = gzip.NewReader(file); err != nil {
			t.Fatal(err)
		}
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	// The most memory in use while it loads, sampled: the table itself is smaller than that.
	var peak atomic.Uint64
	stop := make(chan struct{})
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()
	started := time.Now()
	table, err := Parse(reader)
	close(stop)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(started)
	runtime.GC()
	runtime.ReadMemStats(&after)
	t.Logf("%d ranges in %v, %.1f MB kept, %.1f MB in use at the most while loading, %d names", table.Len(), took.Round(time.Millisecond), float64(after.HeapAlloc-before.HeapAlloc)/1e6, float64(peak.Load()-before.HeapInuse)/1e6, len(table.names))
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		info, found := table.Lookup(netip.MustParseAddr(address))
		t.Logf("%s -> %v (%v)", address, info, found)
	}
	if table.Len() < 100_000 {
		t.Fatalf("only %d ranges", table.Len())
	}
}
