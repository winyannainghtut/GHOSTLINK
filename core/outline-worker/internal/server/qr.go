// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"errors"
	"fmt"
	"strings"

	"rsc.io/qr"
)

const qrQuiet = 4 // modules of white border scanners need

func qrCode(text string) (*qr.Code, error) {
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		return nil, errors.New("this key is too long for one QR code; share it as text or a file")
	}
	return code, nil
}

// QRSVG renders text as a scalable SVG QR code.
func QRSVG(text string) (string, error) {
	code, err := qrCode(text)
	if err != nil {
		return "", err
	}
	size := code.Size + 2*qrQuiet
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; {
			if !code.Black(x, y) {
				x++
				continue
			}
			start := x
			for x < code.Size && code.Black(x, y) {
				x++
			}
			fmt.Fprintf(&path, "M%d %dh%dv1h-%dz", start+qrQuiet, y+qrQuiet, x-start, x-start)
		}
	}
	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="%s"/></svg>`,
		size, size, size, size, path.String()), nil
}

// QRText renders text as a QR code for terminals: two module rows per line using half
// blocks, forced to black on white so it scans on dark terminals too.
func QRText(text string) (string, error) {
	code, err := qrCode(text)
	if err != nil {
		return "", err
	}
	const quiet = 2
	black := func(x, y int) bool { return code.Black(x-quiet, y-quiet) }
	size := code.Size + 2*quiet
	var out strings.Builder
	for y := 0; y < size; y += 2 {
		out.WriteString("\x1b[30;47m")
		for x := 0; x < size; x++ {
			top, bottom := black(x, y), y+1 < size && black(x, y+1)
			switch {
			case top && bottom:
				out.WriteString("█")
			case top:
				out.WriteString("▀")
			case bottom:
				out.WriteString("▄")
			default:
				out.WriteString(" ")
			}
		}
		out.WriteString("\x1b[0m\n")
	}
	return out.String(), nil
}

// qrContent picks what a key's QR code should carry: WireGuard-family apps scan the .conf,
// everything else scans the access key.
func qrContent(key IssuedKey, content string) (string, error) {
	switch content {
	case "", "auto":
		if key.Config != "" {
			return key.Config, nil
		}
		return key.AccessKey, nil
	case "key":
		return key.AccessKey, nil
	case "conf":
		if key.Config == "" {
			return "", InputError{errors.New("only WireGuard and AmneziaWG keys have a .conf")}
		}
		return key.Config, nil
	}
	return "", InputError{errors.New("content must be auto, key or conf")}
}
