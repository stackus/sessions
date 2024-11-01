package sessions

import (
	"crypto/aes"
	"crypto/cipher"
	"hash"

	"github.com/stackus/errors"
)

// CodecOption is an option for configuring a codec.
//
// The following options are available:
// - WithMaxAge: sets the maximum age of the session cookie
// - WithMinAge: sets the minimum age of the session cookie
// - WithMaxLength: sets the maximum length of the session cookie
// - WithHashFn: sets the hash function used by the codec
// - WithBlockKey: sets the block key used by the codec; aes.NewCipher is used to create the block cipher
// - WithBlock: sets the block cipher used by the codec
// - WithSerializer: sets the serializer used by the codec
type CodecOption interface {
	configureCodec(*codec)
}

type MaxAge int64

func (a MaxAge) configureCodec(c *codec) {
	c.maxAge = int64(a)
}

// WithMaxAge sets the maximum age of the session cookie.
//
// The age is in seconds.
func WithMaxAge(age int64) CodecOption {
	return MaxAge(age)
}

type MinAge int64

func (a MinAge) configureCodec(c *codec) {
	c.minAge = int64(a)
}

// WithMinAge sets the minimum age of the session cookie.
//
// The age is in seconds.
func WithMinAge(age int64) CodecOption {
	return MinAge(age)
}

type MaxLength int

func (l MaxLength) configureCodec(c *codec) {
	c.maxLength = int(l)
}

// WithMaxLength sets the maximum length of the session cookie.
//
// If the length is 0, there is no limit to the size of a session.
func WithMaxLength(length int) CodecOption {
	return MaxLength(length)
}

type HashFn func() hash.Hash

func (f HashFn) configureCodec(c *codec) {
	c.hashFn = f
}

// WithHashFn sets the hash function used by the codec during the steps
// where a HMAC is calculated.
//
// The default hash function is sha256.New.
func WithHashFn(fn func() hash.Hash) CodecOption {
	return HashFn(fn)
}

type BlockKey []byte

func (k BlockKey) configureCodec(c *codec) {
	var err error
	c.block, err = aes.NewCipher(k)
	if err != nil {
		c.err = errors.Join(ErrCreatingBlockCipher, err)
	}
}

// WithBlockKey sets the block key used by the codec.
//
// Recommended key sizes are 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256.
func WithBlockKey(key []byte) CodecOption {
	return BlockKey(key)
}

type Block struct {
	cipher.Block
}

func (b Block) configureCodec(c *codec) {
	c.block = b.Block
}

// WithBlock sets the block cipher used by the codec.
//
// The block cipher is used to encrypt the session cookie.
//
// If the block cipher is nil, the session cookie is not encrypted.
func WithBlock(block cipher.Block) CodecOption {
	return Block{block}
}

type SerializerOption struct {
	Serializer
}

func (o SerializerOption) configureCodec(c *codec) {
	c.serializer = o.Serializer
}

// WithSerializer sets the serializer used by the codec.
//
// The serializer is used to serialize and deserialize the session cookie values.
func WithSerializer(s Serializer) CodecOption {
	return SerializerOption{s}
}
