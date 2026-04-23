package main

import (
	"fmt"
	"os"

	"github.com/siyamsarker/wireshield/agent/internal/config"
)

// runStatus prints a one-shot summary of local agent state. Safe to call
// before enrollment (prints "not enrolled").
func runStatus(args []string) error {
	_ = args
	p := paths()
	if !config.Exists(p) {
		fmt.Println("status: not enrolled")
		fmt.Printf("  config dir: %s (missing files)\n", p.Dir)
		return nil
	}
	c, err := config.Load(p)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fmt.Println("status: enrolled")
	fmt.Printf("  agent id     : %d\n", c.AgentID)
	fmt.Printf("  agent name   : %s\n", c.AgentName)
	fmt.Printf("  server       : %s\n", c.ServerURL)
	fmt.Printf("  wg interface : %s (%s)\n", c.WGInterface, c.WGIPv4)
	fmt.Printf("  advertised   : %v\n", c.AdvertisedCIDRs)
	fmt.Printf("  version      : %s\n", Version)
	return nil
}

// paths resolves the config directory, honouring WIRESHIELD_AGENT_DIR if set.
func paths() config.Paths {
	if dir := os.Getenv("WIRESHIELD_AGENT_DIR"); dir != "" {
		return config.PathsFor(dir)
	}
	return config.DefaultPaths()
}
