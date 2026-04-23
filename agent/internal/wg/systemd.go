package wg

import (
	"errors"
	"fmt"
	"os/exec"
)

// systemctl is a thin helper; the agent only ever needs enable/start/stop/disable
// against the wg-quick@<iface> template unit. If systemctl is missing we
// return a distinguishable error so callers can print a friendly message
// on non-systemd distros (which we do not officially support, but we
// should not crash).
var errNoSystemctl = errors.New("systemctl not available")

func systemctl(args ...string) error {
	path, err := exec.LookPath("systemctl")
	if err != nil {
		return errNoSystemctl
	}
	cmd := exec.Command(path, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %v: %w: %s", args, err, string(out))
	}
	return nil
}

// EnableAndStart enables a wg-quick@<iface> unit at boot and starts it now.
// Idempotent: calling twice is fine.
func EnableAndStart(iface string) error {
	unit := "wg-quick@" + iface
	if err := systemctl("enable", "--now", unit); err != nil {
		if errors.Is(err, errNoSystemctl) {
			return fmt.Errorf("systemd not detected; bring up %s manually via: wg-quick up %s", unit, iface)
		}
		return err
	}
	return nil
}

// DisableAndStop brings the interface down and prevents it from starting
// on next boot. Failures are returned so revoke can report cleanly, but
// errors about units that are already stopped/disabled are tolerated
// upstream by the caller checking the exit status of subsequent calls.
func DisableAndStop(iface string) error {
	unit := "wg-quick@" + iface
	if err := systemctl("disable", "--now", unit); err != nil {
		if errors.Is(err, errNoSystemctl) {
			return fmt.Errorf("systemd not detected; bring down %s manually via: wg-quick down %s", unit, iface)
		}
		return err
	}
	return nil
}
