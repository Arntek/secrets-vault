//go:build darwin

package agent

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID returns the effective UID of the process on the other end of a
// Unix socket connection (LOCAL_PEERCRED, the getpeereid mechanism).
func peerUID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return -1, errNoPeerCred
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var uid int
	var serr error
	if err := raw.Control(func(fd uintptr) {
		x, e := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED) // #nosec G115 -- fd fits int
		if e != nil {
			serr = e
			return
		}
		uid = int(x.Uid)
	}); err != nil {
		return -1, err
	}
	if serr != nil {
		return -1, serr
	}
	return uid, nil
}
