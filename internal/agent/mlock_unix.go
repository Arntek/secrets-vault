//go:build unix

package agent

import "syscall"

// lockMemory asks the OS to keep b out of swap. Best effort: RLIMIT_MEMLOCK
// may refuse, and a refusal is not fatal (the key never touches disk by our
// own code either way).
func lockMemory(b []byte) { _ = syscall.Mlock(b) }

func unlockMemory(b []byte) { _ = syscall.Munlock(b) }
