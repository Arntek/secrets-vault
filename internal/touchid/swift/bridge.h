// C interface to the Swift Secure Enclave bridge (TouchIDBridge.swift).
// Only internal/touchid (darwin, cgo, build tag "touchid") includes this.
//
// Every function returns one of the SVTID_* status codes. Buffers are
// caller-owned; the Swift side never allocates memory the caller must free.
#ifndef SVTID_BRIDGE_H
#define SVTID_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#define SVTID_OK            0
#define SVTID_NO_ENCLAVE    1 // no Secure Enclave on this Mac
#define SVTID_NO_BIOMETRY   2 // no sensor, none enrolled, lid closed, locked out
#define SVTID_CANCELLED     3 // user, system or app cancelled the sheet
#define SVTID_AUTH_FAILED   4 // fingerprint not recognised / not authorised
#define SVTID_BAD_KEY       5 // blob or public key could not be loaded
#define SVTID_BUFFER        6 // output buffer too small
#define SVTID_FAILED        7 // anything else

#define SVTID_PUBKEY_LEN 65 // P-256 uncompressed (X9.63) point
#define SVTID_SHARED_LEN 32 // P-256 ECDH shared secret (x coordinate)

int svtid_check(void);
int svtid_create(uint8_t *blob, size_t blob_cap, size_t *blob_len, uint8_t *pub);
int svtid_public_key(const uint8_t *blob, size_t blob_len, uint8_t *pub);
int svtid_agree(const uint8_t *blob, size_t blob_len, const uint8_t *peer,
                const char *reason, uint8_t *shared);

#endif
