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

// verifyPasswordCheck is the check both entry points below perform. RAR5
// records the same PBKDF2-HMAC-SHA256 check value in two places -- the
// archive-level HEAD_CRYPT block and each encrypted file header's encryption
// record -- and the verification is identical; only the struct the fields
// come from differs.
//
// One copy rather than two because this is the code that decides whether a
// password is right. Two copies of it drift, and a drift here is a wrong
// answer about credentials rather than a formatting inconsistency.
//
// hasCheckValue=false means the archive recorded nothing to compare against,
// which is not a failed verification: callers must be able to tell "this
// password is definitely wrong" from "this cannot be decided without trying".
//
// No key material reaches an error from here. The derived bytes stay local
// and the only error values are the sentinels and the KdfCount bound.
func verifyPasswordCheck(kdfCount int, salt, checkValue []byte, password string) (verified, hasCheckValue bool, err error) {
	if checkValue == nil {
		return false, false, nil
	}
	if password == "" {
		return false, true, ErrPasswordRequired
	}
	const maxKdfCount = 24
	if kdfCount > maxKdfCount {
		return false, true, errKdfCountExceeded(kdfCount, maxKdfCount)
	}
	_, pswCheckVal := pbkdf2HmacSha256([]byte(password), salt, 1<<kdfCount)
	if verifyErr := verifyEncCheck(pswCheckVal, checkValue); verifyErr != nil {
		// A mismatch is an answer, not a failure: report it as
		// verified=false with a nil error so a caller can keep trying
		// candidates. Anything else is a real problem with the archive.
		if errors.Is(verifyErr, ErrWrongPassword) {
			return false, true, nil
		}
		return false, true, verifyErr
	}
	return true, true, nil
}

// verifyCryptHeaderPassword reports whether password matches the archive's embedded
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
func verifyCryptHeaderPassword(ch *cryptHeader, password string) (verified bool, hasCheckValue bool, err error) {
	if ch == nil {
		return false, false, errors.New("rarengine: nil crypt header")
	}
	return verifyPasswordCheck(ch.KdfCount, ch.Salt, ch.CheckValue, password)
}

// verifyFileHeaderPassword reports whether password matches a file header's
// embedded per-file content-encryption check value (fh.EncCheck) -- used
// when the archive's own headers are plaintext and only file content is
// encrypted. Same semantics as VerifyPassword: hasCheckValue distinguishes
// "no check value present" from a definite verification result.
//
// This reuses the same derivation/check logic that Reader.buildChain
// already runs lazily during extraction setup (reader.go), exposed
// standalone so it can be checked ahead of extraction.
func verifyFileHeaderPassword(fh *FileHeader, password string) (verified bool, hasCheckValue bool, err error) {
	if fh == nil {
		return false, false, errors.New("rarengine: nil file header")
	}
	return verifyPasswordCheck(fh.KdfCount, fh.Salt, fh.EncCheck, password)
}
