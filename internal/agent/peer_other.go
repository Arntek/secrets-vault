//go:build unix && !linux && !darwin

package agent

import "net"

// peerUID fails closed on Unix systems without a supported credential API.
func peerUID(net.Conn) (int, error) { return -1, errNoPeerCred }
