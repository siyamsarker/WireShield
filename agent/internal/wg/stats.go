package wg

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// TransferStats is the sum of rx_bytes and tx_bytes across all peers on an
// interface. For the agent interface that is exactly one peer (the VPN
// server) — summing is still safe and future-proof.
type TransferStats struct {
	RXBytes int64
	TXBytes int64
}

// ReadTransfer runs `wg show <iface> transfer` and parses the output.
// Missing interface -> returns a zero-value stats and a non-nil error,
// letting the daemon keep looping while logging.
//
// Output format is one line per peer:
//   <pubkey>\t<rx>\t<tx>
func ReadTransfer(iface string) (TransferStats, error) {
	path, err := exec.LookPath("wg")
	if err != nil {
		return TransferStats{}, fmt.Errorf("wg not found in PATH: %w", err)
	}
	out, err := exec.Command(path, "show", iface, "transfer").Output()
	if err != nil {
		return TransferStats{}, fmt.Errorf("wg show %s transfer: %w", iface, err)
	}
	return parseTransfer(string(out))
}

func parseTransfer(out string) (TransferStats, error) {
	var stats TransferStats
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		rx, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return TransferStats{}, fmt.Errorf("parse rx %q: %w", fields[1], err)
		}
		tx, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return TransferStats{}, fmt.Errorf("parse tx %q: %w", fields[2], err)
		}
		stats.RXBytes += rx
		stats.TXBytes += tx
	}
	return stats, scanner.Err()
}
