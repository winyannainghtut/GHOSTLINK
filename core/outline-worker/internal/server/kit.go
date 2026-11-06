// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"bytes"
	"html/template"
	"time"
)

// appHelp tells the person receiving a kit which apps take each kind of key.
var appHelp = map[string][]string{
	Shadowsocks: {
		"Outline (Android, iOS, Windows, macOS, Linux): Add server, then paste the key or scan the code.",
		"Also works in Shadowrocket, v2rayNG, Hiddify and Ghostlink.",
	},
	VLESS: {
		"Android: v2rayNG or Hiddify. iPhone/iPad: Streisand, FoXray or Shadowrocket. Windows/macOS: Hiddify, v2rayN or Ghostlink.",
		"Import from the clipboard, or scan the code.",
	},
	WireGuard: {
		"WireGuard app: tap +, then Scan from QR code (or import the .conf file).",
		"AmneziaVPN: paste the vpn:// key. Ghostlink: Import a file.",
	},
	AmneziaWG: {
		"AmneziaWG app: tap +, then Scan from QR code (or import the .conf file).",
		"AmneziaVPN: paste the vpn:// key. Ghostlink: Add access key with the vpn:// key.",
	},
	IKEv2: {
		"iPhone, iPad or Mac, with no app: open the .mobileconfig file you were sent (AirDrop, Mail or Files).",
		"iPhone/iPad: Settings shows Profile Downloaded; tap it, then Install (on iOS 16 and later: Settings > General > VPN & Device Management). Mac: double-click the file, then System Settings > Privacy & Security > Profiles.",
		"Then turn the VPN on in Settings > VPN.",
	},
	IPsec: {
		"iPhone, iPad or Mac, with no app: open the .mobileconfig file you were sent and install it as for IKEv2.",
		"This is the older IPsec (IKEv1) type; prefer the IKEv2 profile when you have both.",
	},
}

var protocolTitles = map[string]string{
	AmneziaWG: "AmneziaWG", WireGuard: "WireGuard", VLESS: "VLESS with REALITY", Shadowsocks: "Shadowsocks (Outline)",
	IKEv2: "IKEv2 (iPhone, iPad, Mac)", IPsec: "IPsec (iPhone, iPad, Mac; legacy)",
}

var kitTemplate = template.Must(template.New("kit").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.User}} · {{.Server}}</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;margin:0;background:#f3f5f5;color:#243432}
main{max-width:760px;margin:0 auto;padding:28px 18px 60px}
h1{font-size:26px;margin:0 0 6px}p{line-height:1.6}
.note{background:#fff7e6;border:1px solid #f0d9a8;border-radius:8px;padding:12px 14px;font-size:14px}
section{background:#fff;border:1px solid #dbe4e1;border-radius:10px;padding:18px;margin-top:18px}
h2{font-size:18px;margin:0 0 8px}ul{padding-left:18px;margin:6px 0 14px}li{margin:4px 0}
.qr{width:260px;max-width:100%;display:block;margin:10px 0}
textarea{width:100%;box-sizing:border-box;font:12px ui-monospace,Consolas,monospace;border:1px solid #dbe4e1;border-radius:6px;padding:8px;resize:vertical}
small{color:#647571}
</style></head><body><main>
<h1>Your VPN connection</h1>
<p>For <strong>{{.User}}</strong> on <strong>{{.Server}}</strong>. Pick one connection below and add it to the app named there.</p>
<p class="note">Keep this page private. Anyone with these keys can use this connection.</p>
{{range .Keys}}<section>
<h2>{{.Title}}</h2>
<ul>{{range .Help}}<li>{{.}}</li>{{end}}</ul>
{{if .QR}}<div class="qr">{{.QR}}</div><small>{{.QRNote}}</small>{{end}}
{{if .AccessKey}}<p><strong>Key</strong></p><textarea rows="3" readonly>{{.AccessKey}}</textarea>{{else}}<p><strong>Install with the .mobileconfig file</strong> sent with this page (identity <code>{{.Identity}}</code>).</p>{{end}}
{{if .Config}}<p><strong>.conf file</strong> <small>(save as {{.ConfName}})</small></p><textarea rows="9" readonly>{{.Config}}</textarea>{{end}}
</section>{{end}}
<p><small>Created {{.Created}} by Ghostlink server.</small></p>
</main></body></html>
`))

type kitKey struct {
	Title, AccessKey, Config, ConfName, QRNote, Identity string
	Help                                                 []string
	QR                                                   template.HTML
}

// Kit renders a self-contained HTML page with all of a user's keys, QR codes and app help.
func (s *State) Kit(user *User) (string, error) {
	data := struct {
		User, Server, Created string
		Keys                  []kitKey
	}{User: user.Name, Server: s.Name, Created: time.Now().UTC().Format("2 Jan 2006 15:04 UTC")}
	for _, key := range user.Keys {
		issued, err := s.Render(user, key)
		if err != nil {
			return "", err
		}
		entry := kitKey{Title: protocolTitles[key.Protocol], AccessKey: issued.AccessKey, Config: issued.Config, Help: appHelp[key.Protocol], Identity: issued.Identity}
		if issued.Config != "" {
			entry.ConfName = "ghostlink-" + key.Protocol + ".conf"
			entry.QRNote = "This code carries the .conf for the WireGuard or AmneziaWG app."
		}
		content, _ := qrContent(issued, "auto")
		if svg, err := QRSVG(content); err == nil {
			entry.QR = template.HTML(svg) // generated here from module data only
		}
		data.Keys = append(data.Keys, entry)
	}
	var out bytes.Buffer
	if err := kitTemplate.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}
