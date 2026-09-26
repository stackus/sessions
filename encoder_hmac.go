package sessions

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/stackus/errors"
)

const (
	hmacEncoderVersion byte = 1
	hmacMinKeySize          = 32
)

// HMACEncoder authenticates records with HMAC-SHA256.
//
// It provides authenticity and integrity: a record that was altered, or that
// was produced with a different key or label, fails to decode. It does NOT
// conceal the data. Anyone holding an encoded record, such as the client of a
// CookieStore session, can read the session values. Use AESGCMEncoder when
// the values must stay confidential.
//
// The encoded format is version (1 byte) || payload || tag (32 bytes), where
// the tag covers the version, the optional label (see WithEncoderLabel), and
// the payload.
type HMACEncoder struct {
	key   []byte
	label []byte
}

var _ Encoder = (*HMACEncoder)(nil)

// NewHMACEncoder returns an HMACEncoder that signs with key. The key must be
// at least 32 bytes of high-entropy random data; it is copied, so later
// changes to the caller's slice have no effect.
func NewHMACEncoder(key []byte, opts ...EncoderOption) (*HMACEncoder, error) {
	if len(key) < hmacMinKeySize {
		return nil, errors.ErrInvalidArgument.Msgf("hmac encoder: key must be at least %d bytes, got %d", hmacMinKeySize, len(key))
	}

	cfg := newEncoderConfig(opts)

	return &HMACEncoder{
		key:   bytes.Clone(key),
		label: cfg.label,
	}, nil
}

// Encode returns data followed by its authentication tag. The data remains
// readable.
func (e *HMACEncoder) Encode(data []byte) ([]byte, error) {
	out := make([]byte, 0, 1+len(data)+sha256.Size)
	out = append(out, hmacEncoderVersion)
	out = append(out, data...)

	return e.appendTag(out, hmacEncoderVersion, data), nil
}

// Decode verifies the tag and returns a copy of the payload. Truncated,
// altered, or foreign input returns an error matching ErrInvalidEncoding.
func (e *HMACEncoder) Decode(data []byte) ([]byte, error) {
	if len(data) < 1+sha256.Size {
		return nil, ErrInvalidEncoding.Msg("hmac: data too short")
	}

	version := data[0]
	if version != hmacEncoderVersion {
		return nil, ErrInvalidEncoding.Msgf("hmac: unsupported version %d", version)
	}

	payload := data[1 : len(data)-sha256.Size]
	tag := data[len(data)-sha256.Size:]

	if !hmac.Equal(tag, e.appendTag(nil, version, payload)) {
		return nil, ErrInvalidEncoding.Msg("hmac: authentication failed")
	}

	return bytes.Clone(payload), nil
}

// appendTag appends the tag over version || len(label) || label || payload to
// dst. Length-prefixing the label keeps the label/payload boundary unambiguous.
func (e *HMACEncoder) appendTag(dst []byte, version byte, payload []byte) []byte {
	var labelLen [8]byte
	binary.BigEndian.PutUint64(labelLen[:], uint64(len(e.label)))

	h := hmac.New(sha256.New, e.key)
	h.Write([]byte{version})
	h.Write(labelLen[:])
	h.Write(e.label)
	h.Write(payload)

	return h.Sum(dst)
}
