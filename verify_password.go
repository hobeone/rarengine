package rarengine

import (
	"errors"
	"fmt"
)

// errKdfCountExceeded builds the error returned when a header/file's
// declared KdfCount exceeds the sanity ceiling also enforced by
// headerKeyFromPassword and Reader.buildChain.
func errKdfCountExceeded(got, max int) error {
	return fmt.Errorf("rarengine: KdfCount %d exceeds maximum %d", got, max)
}

// VerifyPassword reports whether password matches the archive's embedded
// header-encryption check value (RAR5 HEAD_CRYPT, "store password check
// value" -- the default for modern RAR), without decrypting any header
// content beyond the check itself. It requires ch.CheckValue to be present;
// hasCheckValue reports whether it was, so callers can distinguish
// "definitely wrong" (hasCheckValue=true, verified=false) from "archive
// carries no check value, can't tell, must try for real"
// (hasCheckValue=false).
//
// This reuses the same PBKDF2-HMAC-SHA256 derivation and check-value fold
// (pbkdf2HmacSha256, verifyEncCheck) that headerKeyFromPassword uses at
// header-decrypt time -- it is the same check, exposed standalone so callers
// can verify a password before committing to decrypting/decompressing
// anything.
func VerifyPassword(ch *CryptHeader, password string) (verified bool, hasCheckValue bool, err error) {
	if ch == nil {
		return false, false, errors.New("rarengine: nil crypt header")
	}
	if ch.CheckValue == nil {
		return false, false, nil
	}
	if password == "" {
		return false, true, ErrPasswordRequired
	}
	const maxKdfCount = 24
	if ch.KdfCount > maxKdfCount {
		return false, true, errKdfCountExceeded(ch.KdfCount, maxKdfCount)
	}
	iter := 1 << ch.KdfCount
	_, pswCheckVal := pbkdf2HmacSha256([]byte(password), ch.Salt, iter)
	if verifyErr := verifyEncCheck(pswCheckVal, ch.CheckValue); verifyErr != nil {
		if errors.Is(verifyErr, ErrWrongPassword) {
			return false, true, nil
		}
		return false, true, verifyErr
	}
	return true, true, nil
}

// VerifyFilePassword reports whether password matches a file header's
// embedded per-file content-encryption check value (fh.EncCheck) -- used
// when the archive's own headers are plaintext and only file content is
// encrypted. Same semantics as VerifyPassword: hasCheckValue distinguishes
// "no check value present" from a definite verification result.
//
// This reuses the same derivation/check logic that Reader.buildChain
// already runs lazily during extraction setup (reader.go), exposed
// standalone so it can be checked ahead of extraction.
func VerifyFilePassword(fh *FileHeader, password string) (verified bool, hasCheckValue bool, err error) {
	if fh == nil {
		return false, false, errors.New("rarengine: nil file header")
	}
	if fh.EncCheck == nil {
		return false, false, nil
	}
	if password == "" {
		return false, true, ErrPasswordRequired
	}
	const maxKdfCount = 24
	if fh.KdfCount > maxKdfCount {
		return false, true, errKdfCountExceeded(fh.KdfCount, maxKdfCount)
	}
	iter := 1 << fh.KdfCount
	_, pswCheckVal := pbkdf2HmacSha256([]byte(password), fh.Salt, iter)
	if verifyErr := verifyEncCheck(pswCheckVal, fh.EncCheck); verifyErr != nil {
		if errors.Is(verifyErr, ErrWrongPassword) {
			return false, true, nil
		}
		return false, true, verifyErr
	}
	return true, true, nil
}
