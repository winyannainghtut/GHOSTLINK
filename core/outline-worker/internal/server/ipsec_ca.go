// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
	"software.sslmate.com/src/go-pkcs12"
)

// RSA keeps IKEv1 ("Cisco IPsec") on iOS and macOS working; ECDSA is not accepted everywhere.
const ipsecKeyBits = 3072

// ikeIntermediate is the IKE EKU macOS requires on VPN server certificates.
var ikeIntermediate = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 2, 2}

// Apple accepts server certificates valid for at most 825 days.
const serverCertDays = 825

func pemEncode(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

func parseCertPEM(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKeyPEM(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("not a private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rsaKey, nil
}

func newRSAKey() (*rsa.PrivateKey, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, ipsecKeyBits)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	return key, pemEncode("PRIVATE KEY", der), nil
}

func (s *State) ipsecCAName() string { return "Ghostlink IPsec CA (" + s.Name + ")" }

// serverIdentity is the identity the server presents: its hostname, or its IP address.
func (s *State) serverIdentity() string { return s.Hostname }

// serverNames are the names the server certificate must carry: the hostname and every remote
// identifier an IKEv2 key was given.
func (s *State) serverNames() []string {
	names := []string{s.serverIdentity()}
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if k.RemoteID != "" && !slices.Contains(names, k.RemoteID) {
				names = append(names, k.RemoteID)
			}
		}
	}
	slices.Sort(names[1:])
	return names
}

// ensureIPsecPKI creates the CA, PSK, group name and DNS port on first use and (re)issues the
// server certificate when the address changed or it expires within 60 days.
func (s *State) ensureIPsecPKI(now time.Time, free func(string, uint16) bool) error {
	if s.IPsec.CAPEM == "" {
		key, keyPEM, err := newRSAKey()
		if err != nil {
			return err
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: s.ipsecCAName(), Organization: []string{"Ghostlink"}},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.AddDate(20, 0, 0),
			IsCA:                  true,
			BasicConstraintsValid: true,
			MaxPathLenZero:        true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			return err
		}
		s.IPsec.CAPEM, s.IPsec.CAKeyPEM, s.IPsec.NextSerial = pemEncode("CERTIFICATE", der), keyPEM, 2
	}
	if s.IPsec.PSK == "" {
		s.IPsec.PSK = base64.RawURLEncoding.EncodeToString(random(32))
	}
	if s.IPsec.GroupName == "" {
		s.IPsec.GroupName = defaultGroup
	}
	if s.IPsec.DNSPort == 0 {
		port, err := pickPort(s.usedPorts(), free, "tcp", "udp")
		if err != nil {
			return err
		}
		s.IPsec.DNSPort = port
	}
	renew := s.IPsec.ServerPEM == "" || s.IPsec.ServerFor != strings.Join(s.serverNames(), ",")
	if !renew {
		if cert, err := parseCertPEM(s.IPsec.ServerPEM); err != nil || cert.NotAfter.Before(now.AddDate(0, 0, 60)) {
			renew = true
		}
	}
	if renew {
		return s.issueServerCert(now)
	}
	return nil
}

func (s *State) ipsecCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := parseCertPEM(s.IPsec.CAPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseKeyPEM(s.IPsec.CAKeyPEM)
	return cert, key, err
}

func (s *State) nextSerial() *big.Int {
	if s.IPsec.NextSerial < 2 {
		s.IPsec.NextSerial = 2
	}
	serial := big.NewInt(s.IPsec.NextSerial)
	s.IPsec.NextSerial++
	return serial
}

func (s *State) issueServerCert(now time.Time) error {
	ca, caKey, err := s.ipsecCA()
	if err != nil {
		return err
	}
	key, keyPEM, err := newRSAKey()
	if err != nil {
		return err
	}
	names := s.serverNames()
	template := &x509.Certificate{
		SerialNumber:       s.nextSerial(),
		Subject:            pkix.Name{CommonName: names[0], Organization: []string{"Ghostlink"}},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.AddDate(0, 0, serverCertDays),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{ikeIntermediate},
	}
	for _, name := range names {
		if addr, err := netip.ParseAddr(name); err == nil {
			template.IPAddresses = append(template.IPAddresses, net.IP(addr.AsSlice()))
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	s.IPsec.ServerPEM, s.IPsec.ServerKeyPEM, s.IPsec.ServerFor = pemEncode("CERTIFICATE", der), keyPEM, strings.Join(names, ",")
	return nil
}

// localIdentity is the identity a key uses towards the server (EAP and XAuth name, cert CN).
// A key stores its identity when it is created (see NewKeyWith), so renaming the user changes
// nothing for the device. Only keys from before that have none stored and still derive it.
func (k *Key) localIdentity(user *User) string {
	if k.LocalID != "" {
		return k.LocalID
	}
	return defaultIdentity(user.Name, k.ID)
}

// defaultIdentity is name-ID@ghostlink. The agent accepts an identity only if it starts with a
// letter or digit, so characters the label may keep but that cannot lead (- _ .) are dropped
// from its start, and a name with nothing usable (for example one written in another script)
// becomes "user". A name that already starts with a letter or digit gives the same identity as
// before.
func defaultIdentity(name, keyID string) string {
	label := strings.TrimLeft(strings.ToLower(identityLabel(name)), "-_.")
	if label == "" {
		label = "user"
	}
	return fmt.Sprintf("%s-%s@ghostlink", label, keyID)
}

// pinIdentities stores the identity of every Apple key that has none, so a later rename cannot
// change it, and reports whether it changed anything. A certificate key whose certificate names
// another identity (the old default was refused by the agent for some names, so such a key never
// worked) gets a new certificate for the stored one.
func (s *State) pinIdentities(now time.Time) bool {
	changed := false
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if !k.isApple() || k.LocalID != "" {
				continue
			}
			k.LocalID, changed = k.localIdentity(u), true
			if k.Auth != AuthCertificate {
				continue
			}
			if cert, err := parseCertPEM(k.CertPEM); err == nil && cert.Subject.CommonName != k.LocalID {
				// Best effort: without the CA the old certificate stays as it was.
				revoked := *k
				if s.issueClientCert(u, k, now) == nil {
					s.revoke(&revoked, now)
				}
			}
		}
	}
	return changed
}

// identityLabel keeps the characters IKE identities and file names tolerate.
func identityLabel(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	out := b.String()
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// issueClientCert gives a certificate key its identity, valid for 5 years (revocable by CRL).
func (s *State) issueClientCert(user *User, k *Key, now time.Time) error {
	ca, caKey, err := s.ipsecCA()
	if err != nil {
		return err
	}
	key, keyPEM, err := newRSAKey()
	if err != nil {
		return err
	}
	identity := k.localIdentity(user)
	serial := s.nextSerial()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity, Organization: []string{"Ghostlink"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if strings.Contains(identity, "@") {
		template.EmailAddresses = []string{identity}
	} else {
		template.DNSNames = []string{identity}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	k.CertPEM, k.CertKeyPEM, k.CertSerial = pemEncode("CERTIFICATE", der), keyPEM, serial.Int64()
	k.P12Password = base64.RawURLEncoding.EncodeToString(random(12))
	return nil
}

// revoke records a removed key's certificate so the CRL refuses it.
func (s *State) revoke(k *Key, now time.Time) {
	if k.CertSerial == 0 {
		return
	}
	s.IPsec.Revoked = append(s.IPsec.Revoked, RevokedSerial{Serial: k.CertSerial, At: now.Unix()})
	if len(s.IPsec.Revoked) > maxRevocation {
		s.IPsec.Revoked = s.IPsec.Revoked[len(s.IPsec.Revoked)-maxRevocation:]
	}
}

// CRL lists every revoked client certificate, valid for 7 days (reissued daily). Certificates
// of disabled or over-limit users are put on hold, which strongSwan also refuses; the hold
// ends when the user is active again.
func (s *State) CRL(now time.Time) (string, error) {
	ca, caKey, err := s.ipsecCA()
	if err != nil {
		return "", err
	}
	template := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.AddDate(0, 0, 7),
		RevokedCertificateEntries: s.crlEntries(now),
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, ca, crypto.Signer(caKey))
	if err != nil {
		return "", err
	}
	return pemEncode("X509 CRL", der), nil
}

// crlEntries are the certificates the CRL refuses: revoked ones and those on hold.
func (s *State) crlEntries(now time.Time) []x509.RevocationListEntry {
	var entries []x509.RevocationListEntry
	for _, r := range s.IPsec.Revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: big.NewInt(r.Serial), RevocationTime: time.Unix(r.At, 0),
		})
	}
	active := map[string]bool{}
	for _, u := range s.activeUsers() {
		active[u.ID] = true
	}
	for _, u := range s.Users {
		for _, k := range u.Keys {
			if k.CertSerial != 0 && !active[u.ID] {
				entries = append(entries, x509.RevocationListEntry{
					SerialNumber: big.NewInt(k.CertSerial), RevocationTime: now.Add(-time.Minute), ReasonCode: crlHold,
				})
			}
		}
	}
	return entries
}

// crlHold is the certificateHold reason (RFC 5280), a revocation that can be lifted.
const crlHold = 6

// ntHash is the MD4 of the UTF-16LE password that EAP-MSCHAPv2 uses, so the agent never needs
// the plaintext.
func ntHash(password string) string {
	h := md4.New()
	for _, unit := range utf16.Encode([]rune(password)) {
		h.Write([]byte{byte(unit), byte(unit >> 8)})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// clientP12 bundles a key's certificate and private key for Apple devices (legacy algorithms,
// which iOS requires).
func (s *State) clientP12(k *Key) ([]byte, error) {
	cert, err := parseCertPEM(k.CertPEM)
	if err != nil {
		return nil, err
	}
	key, err := parseKeyPEM(k.CertKeyPEM)
	if err != nil {
		return nil, err
	}
	ca, err := parseCertPEM(s.IPsec.CAPEM)
	if err != nil {
		return nil, err
	}
	return pkcs12.LegacyDES.Encode(key, cert, []*x509.Certificate{ca}, k.P12Password)
}

// stableUUID derives a payload UUID that stays the same for a key, so reinstalling a profile
// replaces it instead of adding a duplicate.
func stableUUID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	h := strings.ToUpper(hex.EncodeToString(b))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
