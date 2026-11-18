//go:build !unix

package agent

func lockMemory([]byte)   {}
func unlockMemory([]byte) {}
