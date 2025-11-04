package wireguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

type Client struct {
	Name    string  `json:"name"`
	Expires *string `json:"expires"`
}

type Service struct {
	ScriptPath string
}

func NewService(scriptPath string) *Service { return &Service{ScriptPath: scriptPath} }

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
	cmd := fmt.Sprintf("source '%s'; ws_list_clients_json", s.ScriptPath)
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
	cmd := fmt.Sprintf("source '%s'; ws_add_client --name %q%s", s.ScriptPath, name, opt)
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
	cmd := fmt.Sprintf("source '%s'; ws_revoke_client %q", s.ScriptPath, name)
	_, err := s.runBash(cmd)
	return err
}

func (s *Service) GetClientConfig(name string) (string, error) {
	cmd := fmt.Sprintf("source '%s'; ws_get_client_config %q", s.ScriptPath, name)
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
	cmd := fmt.Sprintf("source '%s'; ws_check_expired_json", s.ScriptPath)
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

func (s *Service) Restart() error {
	_, err := s.runBash(fmt.Sprintf("source '%s'; restartWireGuard", s.ScriptPath))
	return err
}

func (s *Service) Backup() (string, error) {
	b, err := s.runBash(fmt.Sprintf("source '%s'; backupConfigs", s.ScriptPath))
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
