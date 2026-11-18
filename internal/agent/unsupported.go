//go:build !unix

package agent

import (
	"context"
	"os"
	"os/signal"
)

// Windows (npm, Phase 2) has no agent yet; everything reports ErrUnsupported.

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

// DefaultDir is unsupported on this platform.
func DefaultDir() (string, error) { return "", ErrUnsupported }

// Serve is unsupported on this platform.
func Serve(context.Context, ServerOptions) error { return ErrUnsupported }

// DialWith is unsupported on this platform.
func DialWith(DialOptions) (Client, error) { return nil, ErrUnsupported }
