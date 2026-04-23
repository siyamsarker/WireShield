package main

import "errors"

// runRevoke is implemented in C3 (it shares the WG teardown helpers with the
// daemon's shutdown path).
func runRevoke(args []string) error {
	_ = args
	return errors.New("revoke: not implemented yet")
}
