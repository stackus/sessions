package sessions

import (
	"bytes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"strconv"
	"time"

	"github.com/stackus/errors"
)

type codec struct {
	hashKey     []byte
	hashFn      func() hash.Hash
	block       cipher.Block
	maxLength   int
	maxAge      int64
	minAge      int64
	serializer  Serializer
	timestampFn func() int64
	err         error
}

type Codec interface {
	Encode(name string, src any) ([]byte, error)
	Decode(name string, src []byte, dst any) error
}

// NewCodec returns a new Codec set up with the hash key, optionally configured
// with additional provided CodecOption options.
//
// Codecs are used to encode and optionally encrypt session values. The hashKey
// is required and used to authenticate the cookie value using HMAC. It is
// recommended to use a key with 32 or 64 bytes.
//
// The blockKey is optional and used to encrypt the cookie value. If set, the
// length must correspond to the block size of the encryption algorithm. For
// AES, used by default, valid lengths are 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
//
// Either options or setting sessions.Default* values can be used to configure
// the codec.
func NewCodec(hashKey []byte, options ...CodecOption) Codec {
	c := &codec{
		hashKey:    hashKey,
		hashFn:     DefaultHashFn,
		maxLength:  DefaultMaxLength,
		maxAge:     int64(DefaultMaxAge),
		minAge:     0,
		serializer: DefaultSerializer,
	}

	if len(hashKey) == 0 {
		c.err = ErrHashKeyNotSet
		return c
	}

	for _, option := range options {
		option.configureCodec(c)
	}

	return c
}

// Encode encodes a session value using the codec.
//
// The value is serialized, optionally encrypted, encoded, and a MAC is created to
// validate the value. The value is then encoded using base64.
//
// Processing steps:
//  1. Serialize; customize with WithSerializer
//  2. Encrypt (optional); set with WithBlockKey or WithBlock
//  3. Create MAC; customize with WithHashFn
//  4. Encode using base64.URLEncoding
//  5. Check length (optional); customize with WithMaxLength
func (c *codec) Encode(name string, src any) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}

	var err error
	var data []byte

	// 1. Serialize
	if data, err = c.serializer.Serialize(src); err != nil {
		return nil, errors.Join(ErrSerializeFailed, err)
	}

	// 2. Encrypt (optional)
	if c.block != nil {
		if data, err = c.encrypt(c.block, data); err != nil {
			return nil, err
		}
	}

	data = c.encode(data)

	// 3. Create MAC for "name|date|value with extra pipe to be used later
	data = []byte(fmt.Sprintf("%s|%d|%s|", name, c.timestamp(), data))
	mac := c.createMac(hmac.New(c.hashFn, c.hashKey), data[:len(data)-1])
	data = append(data, mac...)[len(name)+1:]

	// 4. Encode
	data = c.encode(data)

	// 5. Check length
	if c.maxLength != 0 && len(data) > c.maxLength {
		return nil, ErrEncodedLengthTooLong
	}

	return data, nil
}

// Decode decodes a session value using the codec.
//
// The value is decoded using base64, the MAC is validated, decoded, and the
// value is optionally decrypted. The value is then deserialized.
//
// Processing steps:
//  1. Check length (optional); customize with WithMaxLength
//  2. Decode using base64.URLEncoding
//  3. Verify the MAC; customize with WithHashFn
//  4. Verify age; customize with WithMinAge and WithMaxAge
//  5. Decrypt (optional); set with WithBlockKey or WithBlock
//  6. Deserialize; customize with WithSerializer
func (c *codec) Decode(name string, src []byte, dst any) error {
	if c.err != nil {
		return c.err
	}

	// 1. Check length
	if c.maxLength != 0 && len(src) > c.maxLength {
		return ErrEncodedLengthTooLong
	}

	// 2. Decode
	data, err := c.decode(src)
	if err != nil {
		return err
	}

	// 3. Verify the MAC
	parts := bytes.SplitN(data, []byte("|"), 3)
	if len(parts) != 3 {
		return ErrHMACIsInvalid
	}
	h := hmac.New(c.hashFn, c.hashKey)
	data = append([]byte(name+"|"), data[:len(data)-len(parts[2])-1]...)
	if err = c.verifyMac(h, data, parts[2]); err != nil {
		return err
	}

	// 4. Verify age
	var t1 int64
	if t1, err = strconv.ParseInt(string(parts[0]), 10, 64); err != nil {
		return ErrTimestampIsInvalid
	}
	t2 := c.timestamp()
	if c.minAge != 0 && t1 > t2-c.minAge {
		return ErrTimestampIsTooNew
	}
	if c.maxAge != 0 && t1 < t2-c.maxAge {
		return ErrTimestampIsExpired
	}

	data, err = c.decode(parts[1])
	if err != nil {
		return err
	}

	// 5. Decrypt (optional)
	if c.block != nil {
		if data, err = c.decrypt(c.block, data); err != nil {
			return err
		}
	}

	// 6. Deserialize
	if err = c.serializer.Deserialize(data, dst); err != nil {
		return errors.Join(ErrDeserializeFailed, err)
	}

	return nil
}

func (c *codec) encrypt(block cipher.Block, data []byte) ([]byte, error) {
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, errors.Join(ErrGeneratingIV, err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
	return append(iv, data...), nil
}

func (c *codec) decrypt(block cipher.Block, data []byte) ([]byte, error) {
	size := block.BlockSize()
	if len(data) < size {
		return nil, ErrDecryptionFailed
	}

	iv := data[:size]
	data = data[size:]
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

func (c *codec) timestamp() int64 {
	if c.timestampFn != nil {
		return c.timestampFn()
	}
	return time.Now().UTC().Unix()
}

func (c *codec) verifyMac(h hash.Hash, value []byte, mac []byte) error {
	mac2 := c.createMac(h, value)
	if subtle.ConstantTimeCompare(mac, mac2) == 1 {
		return nil
	}
	return ErrHMACIsInvalid
}

func (c *codec) createMac(h hash.Hash, value []byte) []byte {
	h.Write(value)
	return h.Sum(nil)
}

func (c *codec) encode(value []byte) []byte {
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return encoded
}

// decode decodes a cookie using base64.
func (c *codec) decode(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	b, err := base64.URLEncoding.Decode(decoded, value)
	if err != nil {
		return nil, err
	}
	return decoded[:b], nil
}
