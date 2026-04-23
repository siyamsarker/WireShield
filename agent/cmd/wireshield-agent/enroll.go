package main

import "errors"

// runEnroll is implemented in C2.
func runEnroll(args []string) error {
	_ = args
	return errors.New("enroll: not implemented yet")
}
