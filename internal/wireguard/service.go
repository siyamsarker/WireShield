package wireguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Client struct {
	Name    string  `json:"name"`
	Expires *string `json:"expires"`
}

// PeerStat represents a live peer status derived from `wg show` combined with config mapping.
type PeerStat struct {
	Name            string  `json:"name"`
	PublicKey       string  `json:"public_key"`
	Endpoint        string  `json:"endpoint"`
	LatestHandshake string  `json:"latest_handshake"`
	HandshakeAgoSec int     `json:"handshake_ago_sec"`
	ReceiveBytes    int64   `json:"rx_bytes"`
	TransmitBytes   int64   `json:"tx_bytes"`
	AllowedIPs      string  `json:"allowed_ips"`
	Expires         *string `json:"expires,omitempty"`
}

type Service struct {
	ScriptPath string
}

func NewService(scriptPath string) *Service { return &Service{ScriptPath: scriptPath} }

// bashSource builds a robust bash snippet that sources the managing script from
// the first existing candidate path. This makes the dashboard resilient to
// environment mismatches or moved scripts.
func (s *Service) bashSource() string {
	candidates := []string{
		s.ScriptPath,
		"/usr/local/bin/wireshield.sh",
		"/root/wireshield.sh",
		"/home/ubuntu/wireshield.sh",
	}
	parts := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if c == "" { // skip empty
			continue
		}
		parts = append(parts, fmt.Sprintf("source '%s' 2>/dev/null", c))
	}
	// Try command -v as a last resort
	parts = append(parts, "p=$(command -v wireshield.sh 2>/dev/null); [ -n \"$p\" ] && source \"$p\" 2>/dev/null")
	// Join with ORs and add a friendly error if nothing could be sourced
	return fmt.Sprintf("(%s) || { echo 'wireshield.sh not found - set WIRE_SHIELD_SCRIPT or install to /usr/local/bin/wireshield.sh' >&2; exit 127; }", strings.Join(parts, " || "))
}

func (s *Service) runBash(command string) ([]byte, error) {
	cmd := exec.Command("bash", "-lc", command)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("cmd error: %v: %s", err, errb.String())
	}
	return out.Bytes(), nil
}

func (s *Service) ListClients() ([]Client, error) {
	cmd := fmt.Sprintf("%s; ws_list_clients_json", s.bashSource())
	b, err := s.runBash(cmd)
	if err != nil {
		return nil, err
	}
	var clients []Client
	if err := json.Unmarshal(b, &clients); err != nil {
		return nil, err
	}
	return clients, nil
}

func (s *Service) AddClient(name string, days int) (map[string]any, error) {
	opt := ""
	if days > 0 {
		opt = fmt.Sprintf(" --days %d", days)
	}
	cmd := fmt.Sprintf("%s; ws_add_client --name %q%s", s.bashSource(), name, opt)
	b, err := s.runBash(cmd)
	if err != nil {
		return nil, err
	}
	var res map[string]any
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (s *Service) RevokeClient(name string) error {
	cmd := fmt.Sprintf("%s; ws_revoke_client %q", s.bashSource(), name)
	_, err := s.runBash(cmd)
	return err
}

func (s *Service) GetClientConfig(name string) (string, error) {
	cmd := fmt.Sprintf("%s; ws_get_client_config %q", s.bashSource(), name)
	b, err := s.runBash(cmd)
	if err != nil {
		return "", err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return "", errors.New("empty config")
	}
	return string(b), nil
}

func (s *Service) CheckExpired() ([]string, error) {
	cmd := fmt.Sprintf("%s; ws_check_expired_json", s.bashSource())
	b, err := s.runBash(cmd)
	if err != nil {
		return nil, err
	}
	var res struct {
		Removed []string `json:"removed"`
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}
	return res.Removed, nil
}

func (s *Service) ShowStatus() (string, error) {
	// Directly call wg show for reliability
	out, err := exec.Command("wg", "show").CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func (s *Service) IsRunning() bool {
	// Check if WireGuard is running by trying to execute wg show
	cmd := exec.Command("wg", "show")
	err := cmd.Run()
	return err == nil
}

func (s *Service) Restart() error {
	_, err := s.runBash(fmt.Sprintf("%s; restartWireGuard", s.bashSource()))
	return err
}

func (s *Service) Backup() (string, error) {
	b, err := s.runBash(fmt.Sprintf("%s; backupConfigs", s.bashSource()))
	if err != nil {
		return "", err
	}
	// parse path from output
	re := regexp.MustCompile(`Backup saved to (.*)`)
	m := re.FindStringSubmatch(strings.TrimSpace(string(b)))
	if len(m) >= 2 {
		return m[1], nil
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Service) Uninstall() error {
	// This will remove WireGuard and likely make dashboard unusable until reboot/redeploy
	_, err := s.runBash(fmt.Sprintf("source '%s'; REMOVE=y; uninstallWg", s.ScriptPath))
	return err
}

// Settings holds a subset of tunables we expose safely via the dashboard.
type Settings struct {
	ServerPort int    `json:"server_port"`
	ClientDNS1 string `json:"client_dns_1"`
	ClientDNS2 string `json:"client_dns_2"`
	AllowedIPs string `json:"allowed_ips"`
	Interface  string `json:"interface"`
}

// GetSettings reads /etc/wireguard/params and returns key values.
func (s *Service) GetSettings() (Settings, error) {
	p, err := readParamsFile()
	if err != nil {
		return Settings{}, err
	}
	port, _ := strconv.Atoi(p["SERVER_PORT"])
	return Settings{
		ServerPort: port,
		ClientDNS1: p["CLIENT_DNS_1"],
		ClientDNS2: p["CLIENT_DNS_2"],
		AllowedIPs: p["ALLOWED_IPS"],
		Interface:  p["SERVER_WG_NIC"],
	}, nil
}

// UpdateSettings updates allowed keys in params file and adjusts wg conf when port changes.
func (s *Service) UpdateSettings(in Settings) error {
	// basic validation
	if in.ServerPort < 1 || in.ServerPort > 65535 {
		return errors.New("invalid port")
	}
	ipRe := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	if in.ClientDNS1 == "" || !ipRe.MatchString(in.ClientDNS1) {
		return errors.New("invalid DNS1")
	}
	if in.ClientDNS2 != "" && !ipRe.MatchString(in.ClientDNS2) {
		return errors.New("invalid DNS2")
	}
	if strings.TrimSpace(in.AllowedIPs) == "" {
		return errors.New("allowed_ips required")
	}

	params, err := readParamsFile()
	if err != nil {
		return err
	}
	oldPort := params["SERVER_PORT"]
	params["SERVER_PORT"] = strconv.Itoa(in.ServerPort)
	params["CLIENT_DNS_1"] = in.ClientDNS1
	if in.ClientDNS2 != "" {
		params["CLIENT_DNS_2"] = in.ClientDNS2
	}
	params["ALLOWED_IPS"] = in.AllowedIPs
	if err := writeParamsFile(params); err != nil {
		return err
	}
	// Update ListenPort in wg config if port changed
	if oldPort != strconv.Itoa(in.ServerPort) {
		nic := params["SERVER_WG_NIC"]
		if nic == "" {
			nic = in.Interface
		}
		if nic != "" {
			cfg := "/etc/wireguard/" + nic + ".conf"
			b, err := ioutil.ReadFile(cfg)
			if err == nil {
				text := string(b)
				re := regexp.MustCompile(`(?m)^ListenPort\s*=\s*\d+\s*$`)
				text = re.ReplaceAllString(text, "ListenPort = "+strconv.Itoa(in.ServerPort))
				_ = ioutil.WriteFile(cfg, []byte(text), 0600)
			}
		}
		// restart service to apply new port
		_ = s.Restart()
	}
	return nil
}

func readParamsFile() (map[string]string, error) {
	b, err := ioutil.ReadFile("/etc/wireguard/params")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "="); i > 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			m[k] = v
		}
	}
	return m, nil
}

func writeParamsFile(m map[string]string) error {
	// Reconstruct with the keys we know while preserving a stable order
	keys := []string{"SERVER_PUB_IP", "SERVER_PUB_NIC", "SERVER_WG_NIC", "SERVER_WG_IPV4", "SERVER_WG_IPV6", "SERVER_PORT", "SERVER_PRIV_KEY", "SERVER_PUB_KEY", "CLIENT_DNS_1", "CLIENT_DNS_2", "ALLOWED_IPS"}
	var sb strings.Builder
	for _, k := range keys {
		if v, ok := m[k]; ok {
			sb.WriteString(k + "=" + v + "\n")
		}
	}
	return ioutil.WriteFile("/etc/wireguard/params", []byte(sb.String()), 0600)
}

// Restore replaces /etc/wireguard with the content of the provided tar.gz archive
// and attempts to reload the WireGuard interface found in the restored params file.
func (s *Service) Restore(archivePath string) error {
	if strings.TrimSpace(archivePath) == "" {
		return errors.New("empty archive path")
	}
	// The script will:
	// 1) create a timestamped backup of current /etc/wireguard if exists
	// 2) extract provided archive into /tmp/ws-restore-XXXX
	// 3) move extracted etc/wireguard content into place
	// 4) reload wg-quick@<nic> based on params file
	bash := fmt.Sprintf(`set -e
tmpd=$(mktemp -d)
tar xzf %q -C "$tmpd"
ts=$(date +%%Y%%m%%d-%%H%%M%%S)
if [ -d /etc/wireguard ]; then mv /etc/wireguard "/etc/wireguard.bak-$ts"; fi
if [ -d "$tmpd/etc/wireguard" ]; then
	mkdir -p /etc
	mv "$tmpd/etc/wireguard" /etc/wireguard
else
	# archive may directly contain wireguard dir
	if [ -d "$tmpd/wireguard" ]; then mv "$tmpd/wireguard" /etc/wireguard; else echo 'archive missing wireguard dir' >&2; exit 1; fi
fi
chmod -R 600 /etc/wireguard || true
if [ -f /etc/wireguard/params ]; then source /etc/wireguard/params; fi
if command -v systemctl >/dev/null 2>&1 && [ -n "$SERVER_WG_NIC" ]; then systemctl restart "wg-quick@$SERVER_WG_NIC" || true; fi
rm -rf "$tmpd"`, archivePath)
	_, err := s.runBash(bash)
	return err
}

// TransferTotals returns total RX and TX bytes across all peers by parsing
// `wg show all dump`, which exposes exact byte counters.
func (s *Service) TransferTotals() (int64, int64, error) {
	out, err := exec.Command("wg", "show", "all", "dump").CombinedOutput()
	if err != nil {
		return 0, 0, err
	}
	var rxTotal, txTotal int64
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		// Peer lines have at least 9 columns, indexes:
		// 0: iface, 1: public-key, 2: preshared-key, 3: endpoint,
		// 4: allowed-ips, 5: latest-handshake, 6: rx, 7: tx, 8: keepalive
		if len(f) >= 9 {
			rx, _ := strconv.ParseInt(f[6], 10, 64)
			tx, _ := strconv.ParseInt(f[7], 10, 64)
			rxTotal += rx
			txTotal += tx
		}
	}
	return rxTotal, txTotal, nil
}

// PeerStats parses `wg show` output and maps peers to client names & expiration.
// Falls back gracefully if wg is not available.
func (s *Service) PeerStats() ([]PeerStat, error) {
	out, err := exec.Command("wg", "show").CombinedOutput()
	if err != nil {
		return nil, err
	}
	text := string(out)
	// Build map[publicKey]PeerStat skeleton
	endpointRe := regexp.MustCompile(`(?m)^\s+endpoint: (.+)$`)
	allowedRe := regexp.MustCompile(`(?m)^\s+allowed ips: (.+)$`)
	latestHSRe := regexp.MustCompile(`(?m)^\s+latest handshake: (.+)$`)
	transferRe := regexp.MustCompile(`(?m)^\s+transfer: (.+)$`)

	lines := strings.Split(text, "\n")
	var stats []PeerStat
	var current *PeerStat
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "peer: ") {
			pk := strings.TrimSpace(strings.TrimPrefix(line, "peer: "))
			ps := PeerStat{PublicKey: pk}
			stats = append(stats, ps)
			current = &stats[len(stats)-1]
			continue
		}
		if current == nil {
			continue
		}
		if m := endpointRe.FindStringSubmatch(line); len(m) == 2 {
			current.Endpoint = strings.TrimSpace(m[1])
		}
		if m := allowedRe.FindStringSubmatch(line); len(m) == 2 {
			current.AllowedIPs = strings.TrimSpace(m[1])
		}
		if m := latestHSRe.FindStringSubmatch(line); len(m) == 2 {
			val := strings.TrimSpace(m[1])
			current.LatestHandshake = val
			// Attempt to derive seconds ago when format like "3 minutes, 20 seconds ago"
			if strings.HasSuffix(val, " ago") {
				agoStr := strings.TrimSuffix(val, " ago")
				current.HandshakeAgoSec = parseAgoToSeconds(agoStr)
			}
		}
		if m := transferRe.FindStringSubmatch(line); len(m) == 2 {
			// format: "12.34 KiB received, 56.78 KiB sent"
			parts := strings.Split(m[1], ",")
			if len(parts) == 2 {
				rx := strings.TrimSpace(strings.TrimSuffix(parts[0], " received"))
				tx := strings.TrimSpace(strings.TrimSuffix(parts[1], " sent"))
				current.ReceiveBytes = humanToBytes(rx)
				current.TransmitBytes = humanToBytes(tx)
			}
		}
	}

	// Map public keys to names & expiration from config file if available
	cfgPath, err := s.detectConfigPath()
	if err == nil {
		b, readErr := os.ReadFile(cfgPath)
		if readErr == nil {
			pkToName, pkToExpiry := parseConfigForClients(string(b))
			for i := range stats {
				if name, ok := pkToName[stats[i].PublicKey]; ok {
					stats[i].Name = name
					if exp, ok2 := pkToExpiry[stats[i].PublicKey]; ok2 {
						stats[i].Expires = &exp
					}
				}
			}
		}
	}
	return stats, nil
}

func (s *Service) detectConfigPath() (string, error) {
	// We attempt to list clients to infer interface name from first client's config path or environment.
	// Simplified: look for /etc/wireguard/*.conf and choose the one containing "### Client" markers.
	out, err := exec.Command("bash", "-lc", "ls /etc/wireguard/*.conf 2>/dev/null").CombinedOutput()
	if err != nil {
		return "", err
	}
	files := strings.Fields(string(out))
	for _, f := range files {
		b, e := os.ReadFile(f)
		if e == nil && strings.Contains(string(b), "### Client") {
			return f, nil
		}
	}
	return "", errors.New("no wireguard config found")
}

func parseConfigForClients(cfg string) (map[string]string, map[string]string) {
	pkToName := make(map[string]string)
	pkToExpiry := make(map[string]string)
	lines := strings.Split(cfg, "\n")
	var currentName string
	var currentExpiry string
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "### Client ") {
			// Format maybe: ### Client NAME | Expires: YYYY-MM-DD
			parts := strings.Split(line, "Client ")
			if len(parts) == 2 {
				meta := parts[1]
				if segs := strings.Split(meta, "| Expires:"); len(segs) == 2 {
					currentName = strings.TrimSpace(segs[0])
					currentExpiry = strings.TrimSpace(segs[1])
				} else {
					currentName = strings.TrimSpace(meta)
					currentExpiry = ""
				}
			}
			continue
		}
		if strings.HasPrefix(line, "PublicKey = ") && currentName != "" {
			pk := strings.TrimSpace(strings.TrimPrefix(line, "PublicKey = "))
			pkToName[pk] = currentName
			if currentExpiry != "" {
				pkToExpiry[pk] = currentExpiry
			}
			// reset name so we don't accidentally map subsequent keys
			currentName = ""
			currentExpiry = ""
		}
	}
	return pkToName, pkToExpiry
}

// humanToBytes converts sizes like "12.34 KiB" to bytes.
func humanToBytes(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) == 0 {
		return 0
	}
	valStr := parts[0]
	unit := ""
	if len(parts) > 1 {
		unit = parts[1]
	}
	val, _ := parseFloat(valStr)
	mult := float64(1)
	switch strings.ToUpper(unit) {
	case "B":
		mult = 1
	case "KIB":
		mult = 1024
	case "MIB":
		mult = 1024 * 1024
	case "GIB":
		mult = 1024 * 1024 * 1024
	}
	return int64(val * mult)
}

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

// parseAgoToSeconds attempts to interpret strings like "3 minutes, 20 seconds".
func parseAgoToSeconds(s string) int {
	parts := strings.Split(s, ",")
	total := 0
	for _, p := range parts {
		p = strings.TrimSpace(p)
		fields := strings.Fields(p)
		if len(fields) < 2 {
			continue
		}
		valStr := fields[0]
		unit := fields[1]
		v := 0
		fmt.Sscanf(valStr, "%d", &v)
		switch {
		case strings.HasPrefix(unit, "second"):
			total += v
		case strings.HasPrefix(unit, "minute"):
			total += v * 60
		case strings.HasPrefix(unit, "hour"):
			total += v * 3600
		case strings.HasPrefix(unit, "day"):
			total += v * 86400
		}
	}
	return total
}
