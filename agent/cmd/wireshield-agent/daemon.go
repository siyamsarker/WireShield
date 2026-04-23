package main

import "errors"

// runDaemon is implemented in C3.
func runDaemon(args []string) error {
	_ = args
	return errors.New("run: not implemented yet")
}
