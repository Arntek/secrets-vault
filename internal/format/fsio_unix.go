//go:build unix

package format

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// openNoFollow opens path read-only and fails if its last element is a
// symlink, closing the gap between checking and opening.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // #nosec G304 -- vault file path built from validated parts
}

func isSymlinkErr(err error) bool { return errors.Is(err, syscall.ELOOP) }

// ownedByMe reports whether fi belongs to the current user.
func ownedByMe(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid()
}
