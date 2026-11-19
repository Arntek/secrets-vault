//go:build darwin && cgo && touchid

package touchid

// The Swift static library is built by `make touchid-lib` into
// build/touchid at the repository root, and linked through CGO_LDFLAGS set
// by the Makefile (`-L build/touchid -lsvtouchid` plus the toolchain's Swift
// library folders). It can't go in a #cgo LDFLAGS line: since Go 1.27 the
// go command rejects package-supplied archives that carry LLVM sections or
// autolink commands, which every Swift object has. Flags from the
// environment are trusted. The Swift runtime and the CryptoKit,
// LocalAuthentication and Security frameworks come from the library's
// autolink entries.

/*
#cgo CFLAGS: -I${SRCDIR}/swift
#include <stdlib.h>
#include <libproc.h>
#include "bridge.h"

#include <unistd.h>

#define SVTID_NAME_LEN 256

// Writes the parent process's name into buf (SVTID_NAME_LEN bytes) and
// returns its length, or 0.
static int svtid_parent_name(char *buf) {
	int n = proc_name(getppid(), buf, SVTID_NAME_LEN);
	return n > 0 && n < SVTID_NAME_LEN ? n : 0;
}
*/
import "C"

import (
	"unsafe"

	"github.com/Arntek/secrets-vault/internal/testguard"
)

func init() { platform = swiftEnclave{} }

// swiftEnclave is the real Secure Enclave, via the Swift bridge.
type swiftEnclave struct{}

// The status codes in bridge.h must match the ones statusError maps. These
// constant expressions fail to compile if they drift apart.
const (
	_ = uint(C.SVTID_OK - statusOK)
	_ = uint(statusOK - C.SVTID_OK)
	_ = uint(C.SVTID_NO_ENCLAVE - statusNoEnclave)
	_ = uint(statusNoEnclave - C.SVTID_NO_ENCLAVE)
	_ = uint(C.SVTID_NO_BIOMETRY - statusNoBiometry)
	_ = uint(statusNoBiometry - C.SVTID_NO_BIOMETRY)
	_ = uint(C.SVTID_CANCELLED - statusCancelled)
	_ = uint(statusCancelled - C.SVTID_CANCELLED)
	_ = uint(C.SVTID_AUTH_FAILED - statusAuthFailed)
	_ = uint(statusAuthFailed - C.SVTID_AUTH_FAILED)
	_ = uint(C.SVTID_BAD_KEY - statusBadKey)
	_ = uint(statusBadKey - C.SVTID_BAD_KEY)
	_ = uint(C.SVTID_PUBKEY_LEN - pubKeyLen)
	_ = uint(pubKeyLen - C.SVTID_PUBKEY_LEN)
)

func statusErr(rc C.int) error { return statusError(int(rc)) }

func (swiftEnclave) check() error { return statusErr(C.svtid_check()) }

func (swiftEnclave) create() (blob, pub []byte, err error) {
	buf := make([]byte, maxBlobSize)
	pub = make([]byte, pubKeyLen)
	var n C.size_t
	rc := C.svtid_create((*C.uint8_t)(unsafe.Pointer(&buf[0])), C.size_t(len(buf)), &n,
		(*C.uint8_t)(unsafe.Pointer(&pub[0])))
	if err := statusErr(rc); err != nil {
		return nil, nil, err
	}
	if n == 0 || int(n) > len(buf) {
		return nil, nil, errBadKey
	}
	return buf[:n:n], pub, nil
}

func (swiftEnclave) publicKey(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errBadKey
	}
	pub := make([]byte, pubKeyLen)
	rc := C.svtid_public_key((*C.uint8_t)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)),
		(*C.uint8_t)(unsafe.Pointer(&pub[0])))
	if err := statusErr(rc); err != nil {
		return nil, err
	}
	return pub, nil
}

func (swiftEnclave) agree(blob, peer []byte, reason string) ([]byte, error) {
	testguard.Forbid("Touch ID sheet")
	if len(blob) == 0 || len(peer) != pubKeyLen {
		return nil, errBadKey
	}
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))
	shared := make([]byte, C.SVTID_SHARED_LEN)
	rc := C.svtid_agree((*C.uint8_t)(unsafe.Pointer(&blob[0])), C.size_t(len(blob)),
		(*C.uint8_t)(unsafe.Pointer(&peer[0])), cReason,
		(*C.uint8_t)(unsafe.Pointer(&shared[0])))
	if err := statusErr(rc); err != nil {
		clear(shared)
		return nil, err
	}
	return shared, nil
}

func (swiftEnclave) parentProgram() string {
	var buf [C.SVTID_NAME_LEN]C.char
	n := C.svtid_parent_name(&buf[0])
	if n <= 0 {
		return ""
	}
	return C.GoStringN(&buf[0], n)
}
