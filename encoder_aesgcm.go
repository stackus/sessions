package sessions

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/stackus/errors"
)

const aesgcmEncoderVersion byte = 1

// AESGCMEncoder encrypts and authenticates records with AES-GCM.
//
// It provides confidentiality as well as authenticity and integrity: the
// session values cannot be read without the key, and a record that was
// altered, or that was produced with a different key or label, fails to
// decode.
//
// The encoded format is version (1 byte) || nonce (12 bytes) || ciphertext and
// tag. The version and the optional label (see WithEncoderLabel) are
// authenticated as additional data. Every Encode uses a fresh random nonce.
type AESGCMEncoder struct {
	aead cipher.AEAD
	aad  []byte
	rand io.Reader
}

var _ Encoder = (*AESGCMEncoder)(nil)

// NewAESGCMEncoder returns an AESGCMEncoder that encrypts with key. The key
// must be 16, 24, or 32 bytes of high-entropy random data, selecting AES-128,
// AES-192, or AES-256. The encoder does not keep a reference to key.
func NewAESGCMEncoder(key []byte, opts ...EncoderOption) (*AESGCMEncoder, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, errors.ErrInvalidArgument.Msgf("aes-gcm encoder: key must be 16, 24, or 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.ErrInternal.Wrap(err, "aes-gcm encoder: create cipher")
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.ErrInternal.Wrap(err, "aes-gcm encoder: create gcm")
	}

	cfg := newEncoderConfig(opts)

	return &AESGCMEncoder{
		aead: aead,
		aad:  append([]byte{aesgcmEncoderVersion}, cfg.label...),
		rand: rand.Reader,
	}, nil
}

// Encode encrypts data under a fresh random nonce. A failure to read the
// random source is an operational error, not ErrInvalidEncoding.
func (e *AESGCMEncoder) Encode(data []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(e.rand, nonce); err != nil {
		return nil, errors.ErrInternal.Wrap(err, "aes-gcm: generate nonce")
	}

	out := make([]byte, 0, 1+nonceSize+len(data)+e.aead.Overhead())
	out = append(out, aesgcmEncoderVersion)
	out = append(out, nonce...)

	return e.aead.Seal(out, nonce, data, e.aad), nil
}

// Decode authenticates and decrypts data. Truncated, altered, or foreign input
// returns an error matching ErrInvalidEncoding.
func (e *AESGCMEncoder) Decode(data []byte) ([]byte, error) {
	nonceSize := e.aead.NonceSize()

	if len(data) < 1+nonceSize+e.aead.Overhead() {
		return nil, ErrInvalidEncoding.Msg("aes-gcm: data too short")
	}

	if version := data[0]; version != aesgcmEncoderVersion {
		return nil, ErrInvalidEncoding.Msgf("aes-gcm: unsupported version %d", version)
	}

	nonce := data[1 : 1+nonceSize]
	ciphertext := data[1+nonceSize:]
	plaintext, err := e.aead.Open(make([]byte, 0, len(ciphertext)-e.aead.Overhead()), nonce, ciphertext, e.aad)
	if err != nil {
		return nil, ErrInvalidEncoding.Msg("aes-gcm: authentication failed")
	}

	return plaintext, nil
}
