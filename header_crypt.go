package rarengine

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

// CryptHeader holds the parameters decoded from a RAR5 archive encryption
// header (HEAD_CRYPT, header type 4) -- present when the archive's own
// headers, not just file content, are encrypted.
type CryptHeader struct {
	KdfCount   int
	Salt       []byte // 16 bytes, shared by every encrypted header in the archive.
	CheckValue []byte // 12 bytes; nil if the archive carries no password check value.
}

// ParseCryptHeader decodes the archive encryption header payload. Per the
// RAR 5.0 format spec its fields are: encryption version (vint, must be 0 =
// AES-256), encryption flags (vint, bit 0 = password check value present),
// KDF count (1 raw byte), salt (16 bytes), and an optional 12-byte check
// value. Unlike the per-file encryption record (parseEncryptionRecord),
// this header carries no IV -- per spec, every subsequent header instead
// supplies its own fresh IV inline (see headerDecrypter).
func ParseCryptHeader(h *BlockHeader) (*CryptHeader, error) {
	if h.Type != HeaderTypeEncryption {
		return nil, ErrBadBlockHeader
	}
	payload := h.Payload

	ver, n, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	if ver != 0 {
		return nil, ErrUnknownEncryptMethod
	}
	payload = payload[n:]

	flags, n, err := DecodeVint(payload)
	if err != nil {
		return nil, err
	}
	payload = payload[n:]

	if len(payload) < 17 {
		return nil, ErrCorruptEncryptData
	}
	ch := &CryptHeader{
		KdfCount: int(payload[0]),
		Salt:     append([]byte(nil), payload[1:17]...),
	}
	payload = payload[17:]

	if flags&FileEncCheckPresent > 0 {
		if len(payload) < 12 {
			return nil, ErrCorruptEncryptData
		}
		ch.CheckValue = append([]byte(nil), payload[:12]...)
	}
	return ch, nil
}

// headerKeyFromPassword derives the AES-256 key used to decrypt every
// subsequent header in the archive, and verifies password correctness
// against CheckValue when present. Uses the same PBKDF2 scheme as per-file
// content encryption (pbkdf2HmacSha256) -- the RAR 5.0 spec defines one key
// derivation function shared by both header and file encryption.
func headerKeyFromPassword(ch *CryptHeader, password string) ([]byte, error) {
	if password == "" {
		return nil, ErrPasswordRequired
	}
	const maxKdfCount = 24
	if ch.KdfCount > maxKdfCount {
		return nil, fmt.Errorf("rarengine: header KdfCount %d exceeds maximum %d", ch.KdfCount, maxKdfCount)
	}
	iter := 1 << ch.KdfCount
	key, pswCheckVal := pbkdf2HmacSha256([]byte(password), ch.Salt, iter)
	if ch.CheckValue != nil {
		if err := verifyEncCheck(pswCheckVal, ch.CheckValue); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// headerDecrypter decrypts individual RAR5 header blocks once the archive's
// headers are encrypted. Unlike file content, header encryption is not a
// continuous stream cipher: per the RAR 5.0 spec, "every next header...is
// started from [a] 16 byte AES-256 initialization vector followed by
// encrypted header data," so each header block carries its own fresh IV
// that must be read from the stream immediately before it.
type headerDecrypter struct {
	key []byte
}

// readEncryptedBlockHeader reads one IV-prefixed, encrypted RAR5 header
// block from r. It decrypts 16-byte ciphertext blocks incrementally until
// enough plaintext is available to know the header's declared total size
// (from its CRC32+size prefix), then hands off to parseBlockHeaderFields --
// the same field-parsing logic ReadBlockHeader uses once decrypted.
func (hd *headerDecrypter) readEncryptedBlockHeader(r io.Reader) (*BlockHeader, error) {
	iv := make([]byte, 16)
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(hd.key)
	if err != nil {
		return nil, err
	}
	dec := cipher.NewCBCDecrypter(block, iv)

	var plain []byte
	declaredTotal := -1
	vintLen := 0
	for declaredTotal < 0 || len(plain) < declaredTotal {
		ct := make([]byte, 16)
		if _, err := io.ReadFull(r, ct); err != nil {
			return nil, err
		}
		pt := make([]byte, 16)
		dec.CryptBlocks(pt, ct)
		plain = append(plain, pt...)

		if declaredTotal < 0 && len(plain) >= 8 {
			sizeV, n, err := DecodeVint(plain[4:])
			if err != nil {
				return nil, err
			}
			if sizeV > maxHeaderSize {
				return nil, ErrBadBlockHeader
			}
			vintLen = n
			declaredTotal = 4 + n + int(sizeV)
		}
		if len(plain) > maxHeaderSize+32 {
			return nil, ErrBadBlockHeader
		}
	}

	crc := binary.LittleEndian.Uint32(plain[0:4])
	buf := plain[4:declaredTotal]
	hash := crc32.NewIEEE()
	_, _ = hash.Write(buf)
	if crc != hash.Sum32() {
		return nil, ErrBadHeaderCRC
	}

	return parseBlockHeaderFields(buf, vintLen)
}
