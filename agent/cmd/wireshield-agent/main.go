// wireshield-agent is the Go daemon that runs on a remote Linux host and
// joins the WireShield VPN as a special WireGuard peer exposing a LAN.
//
// Subcommands:
//   enroll    — exchange a single-use token for a WG peer config and persist it
//   run       — long-running daemon: heartbeat + revocation polling
//   status    — print current enrollment + WG interface state
//   revoke    — local cleanup (remove config + bring down WG interface)
//   uninstall — full teardown: stop daemon, remove WG tunnel, delete binary + service
//   update    — one-shot self-upgrade against the server's published manifest
//   version   — print the agent version and exit
//
// The binary is intended to be invoked by systemd (for `run`) and by the
// bootstrap install.sh (for `enroll`). Everything is idempotent — running
// `enroll` twice is refused; running `revoke` twice is a no-op.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/siyamsarker/wireshield/agent/internal/logx"
)

// Version is overridden via -ldflags at build time:
//   go build -ldflags "-X main.Version=1.0.0" ...
// The default here is used for dev builds.
var Version = "dev"

func main() {
	logx.SetLevelFromEnv(os.Getenv("WIRESHIELD_AGENT_LOG_LEVEL"))

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "enroll":
		exit(runEnroll(args))
	case "run":
		exit(runDaemon(args))
	case "status":
		exit(runStatus(args))
	case "revoke":
		exit(runRevoke(args))
	case "uninstall":
		exit(runUninstall(args))
	case "update":
		exit(runUpdate(args))
	case "version", "-v", "--version":
		fmt.Println(Version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "wireshield-agent: unknown subcommand %q\n\n", sub)
		usage()
		os.Exit(2)
	}
}

func exit(err error) {
	if err == nil {
		return
	}
	// Strip any trailing newline from the error so our own formatting stays tidy.
	msg := strings.TrimRight(err.Error(), "\n")
	logx.Error("%s", msg)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `wireshield-agent %s — remote LAN gateway for WireShield VPN

usage:
  wireshield-agent <command> [flags]

commands:
  enroll      register this host with the VPN server (one-time)
  run         long-running heartbeat + revocation daemon (used by systemd)
  status      print local enrollment + WG interface state
  revoke      remove local agent config and tear down the WG interface
  uninstall   full teardown: stop daemon, remove tunnel, delete binary + service
  update      one-shot self-upgrade against the server's published manifest
  version     print version
  help        show this message

environment:
  WIRESHIELD_AGENT_DIR        config dir (default /etc/wireshield-agent)
  WIRESHIELD_AGENT_LOG_LEVEL  debug|info|warn|error (default info)

run 'wireshield-agent <command> -h' for command-specific flags.
`, Version)
}
