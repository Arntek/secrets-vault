//go:build unix

package agent

import (
	"errors"
	"net"
	"os"
)

var (
	errNoPeerCred = errors.New("agent: peer credentials unavailable")
	// ErrWrongUser is returned for a connection from another user.
	ErrWrongUser = errors.New("agent: connection from a different user rejected")
)

// authorize accepts a peer only if its UID equals want. Any error reading
// the credentials rejects the connection (fail closed).
func authorize(got int, err error, want int) error {
	if err != nil || got != want {
		return ErrWrongUser
	}
	return nil
}

// checkPeer verifies that the peer of c runs as the same user as this process.
func checkPeer(c net.Conn) error {
	uid, err := peerUID(c)
	return authorize(uid, err, os.Geteuid())
}
