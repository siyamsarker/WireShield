package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/siyamsarker/WireShield/dashboard/config"
	"github.com/siyamsarker/WireShield/dashboard/internal/server"
)

func main() {
	cfgPath := flag.String("config", "/etc/wireshield/dashboard-config.json", "path to dashboard config")
	initUser := flag.String("init-admin", "", "initialize admin username (interactive password prompt)")
	initPass := flag.String("init-admin-pass", "", "initialize admin with given password (non-interactive)")
	listen := flag.String("listen", "", "override listen address (e.g., 127.0.0.1:51821)")
	flag.Parse()

	if *initUser != "" {
		// Initialize admin credentials
		if *initPass == "" {
			fmt.Println("Error: --init-admin-pass is required when using --init-admin non-interactively")
			os.Exit(2)
		}
		if err := config.InitConfig(*cfgPath, *initUser, *initPass); err != nil {
			log.Fatalf("init failed: %v", err)
		}
		fmt.Printf("Initialized config at %s with admin '%s'\n", *cfgPath, *initUser)
		return
	}

	// Load or create default config
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	// Ensure runtime directories
	if err := os.MkdirAll(filepath.Dir(*cfgPath), 0o755); err != nil {
		log.Fatalf("failed to ensure config dir: %v", err)
	}

	srv := server.New(cfg, *cfgPath)
	log.Printf("WireShield Dashboard listening on http://%s", cfg.Listen)
	log.Fatal(srv.Start())
}
