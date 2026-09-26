package sessions

import (
	"encoding/base64"
)

// Base64Encoder encodes records as unpadded base64url text.
//
// Base64 is a reversible representation only. It provides no confidentiality,
// authenticity, or integrity: anyone who can read or write the encoded data
// can read or change the session values. It is suitable only for a trusted
// server-side store, such as FileStore, when the storage environment itself is
// trusted.
//
// Pairing Base64Encoder with CookieStore is insecure: the client can read and
// forge its own session. NewManager does not prevent this combination; use
// HMACEncoder or AESGCMEncoder with CookieStore.
type Base64Encoder struct{}

var _ Encoder = (*Base64Encoder)(nil)

// NewBase64Encoder returns a Base64Encoder.
func NewBase64Encoder() *Base64Encoder {
	return &Base64Encoder{}
}

// Encode returns the unpadded base64url encoding of data.
func (*Base64Encoder) Encode(data []byte) ([]byte, error) {
	dst := make([]byte, base64.RawURLEncoding.EncodedLen(len(data)))
	base64.RawURLEncoding.Encode(dst, data)

	return dst, nil
}

// Decode reverses Encode. Input that is not canonical unpadded base64url
// returns an error matching ErrInvalidEncoding.
func (*Base64Encoder) Decode(data []byte) ([]byte, error) {
	dst := make([]byte, base64.RawURLEncoding.DecodedLen(len(data)))
	n, err := base64.RawURLEncoding.Strict().Decode(dst, data)
	if err != nil {
		return nil, ErrInvalidEncoding.Wrap(err, "base64 decode")
	}

	return dst[:n], nil
}
