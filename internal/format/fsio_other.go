//go:build !unix

package format

import (
	"io/fs"
	"os"
)

// openNoFollow refuses symlinks with a check before opening; readRegular
// then checks the opened file is regular.
func openNoFollow(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, errSymlink
	}
	return os.Open(path) // #nosec G304 -- vault file path built from validated parts
}

var errSymlink = fs.ErrInvalid

func isSymlinkErr(err error) bool { return err == errSymlink }
