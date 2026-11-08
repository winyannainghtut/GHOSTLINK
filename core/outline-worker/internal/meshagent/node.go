// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright 2026 Ghostlink contributors

// Package meshagent is the ghostlink-mesh agent: it joins a Ghostlink mesh, keeps a kernel
// WireGuard interface, routes, firewall chains and an /etc/hosts block in line with the
// configuration the coordinator sends, and reports the link state back. The node's private key
// is created here and never leaves the node.
package meshagent

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"ghostlink.local/outline-worker/internal/meshproto"
)

const (
	// DefaultDir holds node.json (the node's identity, mode 0600) and status.json.
	DefaultDir = "/var/lib/ghostlink-mesh"
	// DefaultInterface is the WireGuard interface.
	DefaultInterface = "glmesh0"
	nodeFile         = "node.json"
	statusFile       = "status.json"
)

var interfacePattern = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

// ValidInterface accepts a Linux interface name the agent may create.
func ValidInterface(name string) bool { return interfacePattern.MatchString(name) }

// Node is this machine's identity in the mesh.
type Node struct {
	URL        string `json:"url"`
	Pin        string `json:"pin"`
	NodeID     string `json:"node_id"`
	Secret     string `json:"secret"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	Interface  string `json:"interface"`
	ListenPort uint16 `json:"listen_port"`
	// Endpoint is the public address other nodes should use, when it can't be detected.
	Endpoint        string   `json:"endpoint,omitempty"`
	AdvertiseRoutes []string `json:"advertise_routes"`
	// Forwarding is this machine's consent to forward packets (as a relay, or to shared
	// subnets). The coordinator can't turn it on by itself: without it the agent installs no
	// forwarding rules, even where IPv4 forwarding is already on.
	Forwarding bool `json:"forwarding"`
	// Hosts keeps <node>.mesh names in /etc/hosts.
	Hosts bool `json:"hosts"`
	// ForwardingBefore is ip_forward from before this node first forwarded, to restore on leave.
	ForwardingBefore string `json:"forwarding_before,omitempty"`
}

// LoadNode reads the node identity from dir.
func LoadNode(dir string) (*Node, error) {
	data, err := os.ReadFile(filepath.Join(dir, nodeFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("this machine is not in a mesh; join with: sudo ghostlink-mesh join (or the command from your Ghostlink server)")
	}
	if err != nil {
		return nil, err
	}
	var n Node
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", filepath.Join(dir, nodeFile), err)
	}
	if !ValidInterface(n.Interface) || !meshproto.ValidKey(n.PrivateKey) || n.NodeID == "" || n.Secret == "" {
		return nil, fmt.Errorf("%s is damaged", filepath.Join(dir, nodeFile))
	}
	return &n, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	temporary := path + ".pending"
	_ = os.Remove(temporary)
	if err := os.WriteFile(temporary, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(temporary, mode); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// Save writes the identity (mode 0600: it holds the private key and the sync secret).
func (n *Node) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(n, "", "  ")
	return writeAtomic(filepath.Join(dir, nodeFile), data, 0o600)
}

// Forget deletes the identity and status.
func Forget(dir string) {
	_ = os.Remove(filepath.Join(dir, nodeFile))
	_ = os.Remove(filepath.Join(dir, statusFile))
}

// ErrRemoved means the coordinator no longer knows this node.
var ErrRemoved = errors.New("this node was removed from the mesh")

// Client talks to the coordinator over TLS 1.3, accepting only the pinned certificate.
type Client struct {
	url  string
	http *http.Client
}

// NewClient returns a client for the coordinator at url with certificate fingerprint pin.
func NewClient(url, pin string) *Client {
	transport := &http.Transport{
		Proxy:               nil,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // replaced by the pin check below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("the coordinator sent no certificate")
				}
				sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if !strings.EqualFold(hex.EncodeToString(sum[:]), pin) {
					return errors.New("the coordinator's certificate does not match the invite (wrong server, or someone in between)")
				}
				return nil
			},
		},
	}
	return &Client{url: strings.TrimRight(url, "/"), http: &http.Client{Transport: transport, Timeout: 40 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *Client) post(ctx context.Context, path, secret string, body, out any) error {
	data, _ := json.Marshal(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+path, strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("cannot reach the mesh coordinator: %w", err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return ErrRemoved
	case response.StatusCode >= 300:
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = response.Status
		}
		return fmt.Errorf("the mesh coordinator refused: %s", e.Error)
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("the mesh coordinator sent an unreadable answer")
		}
	}
	return nil
}

// Join registers the node with an invite token.
func (c *Client) Join(r meshproto.JoinRequest) (meshproto.JoinResponse, error) {
	var out meshproto.JoinResponse
	return out, c.post(context.Background(), "/v1/join", "", r, &out)
}

// Sync reports state and waits (up to about 10 s) for configuration changes.
func (c *Client) Sync(ctx context.Context, secret string, r meshproto.SyncRequest) (meshproto.SyncResponse, error) {
	var out meshproto.SyncResponse
	return out, c.post(ctx, "/v1/sync", secret, r, &out)
}

// Leave removes the node from the mesh.
func (c *Client) Leave(secret string) error {
	return c.post(context.Background(), "/v1/leave", secret, map[string]string{}, nil)
}

// LocalEndpoints lists addresses other nodes may reach this machine at: the configured public
// endpoint first, then the machine's own IPv4 addresses (container and VPN interfaces excluded).
func LocalEndpoints(configured string, port uint16, meshInterface string) []string {
	out := []string{}
	if configured != "" {
		out = append(out, configured)
	}
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		name := iface.Name
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || name == meshInterface {
			continue
		}
		skip := false
		for _, prefix := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "kube", "lxc", "tun", "wg", "tailscale", "zt", "glmesh", "glipsec"} {
			skip = skip || strings.HasPrefix(name, prefix)
		}
		if skip {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil || !ipnet.IP.IsGlobalUnicast() {
				continue
			}
			e := net.JoinHostPort(ipnet.IP.String(), fmt.Sprint(port))
			if len(out) < 16 && e != configured {
				out = append(out, e)
			}
		}
	}
	return out
}

// forwardingUsers names the software that may rely on IPv4 forwarding, judged by the interfaces
// it creates. Docker, libvirt, LXD and the like turn forwarding on only when they start, so
// turning it off under them cuts off their containers and VMs.
func forwardingUsers(interfaces []string) []string {
	known := []struct{ prefix, name string }{
		{"docker", "Docker"}, {"br-", "Docker"}, {"podman", "Podman"}, {"cni", "Kubernetes"}, {"flannel", "Kubernetes"},
		{"cali", "Kubernetes"}, {"cilium", "Kubernetes"}, {"kube", "Kubernetes"}, {"virbr", "libvirt"}, {"lxdbr", "LXD"},
		{"lxcbr", "LXC"}, {"incusbr", "Incus"}, {"wg", "WireGuard"}, {"tun", "a VPN"}, {"glipsec", "IKEv2/IPsec"},
	}
	var out []string
	for _, name := range interfaces {
		for _, k := range known {
			if strings.HasPrefix(name, k.prefix) && !slices.Contains(out, k.name) {
				out = append(out, k.name)
			}
		}
	}
	return out
}

func interfaceNames() []string {
	var names []string
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		names = append(names, iface.Name)
	}
	return names
}
