//go:build windows

package cli

import "errors"

func mkfifo(string) error { return errors.New("no fifos on Windows") }
