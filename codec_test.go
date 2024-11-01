package sessions

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha512"
	"encoding/gob"
	"testing"

	"github.com/stretchr/testify/assert"
)

type timestampFn func() int64

func (fn timestampFn) configureCodec(c *codec) {
	c.timestampFn = fn
}

// withTimestampFn returns a CodecOption that sets the timestampFn of the codec.
// this can be used to simulate time passing in tests.
func withTimestampFn(times []int64) CodecOption {
	return timestampFn(func() int64 {
		if len(times) == 0 {
			return 0
		}
		t := times[0]
		times = times[1:]
		return t
	})
}

func TestCodec(t *testing.T) {
	type sessionData struct {
		Value string
	}

	type testCase struct {
		hashKey       []byte
		options       []CodecOption
		name          string
		src           sessionData
		adjustCodec   func(*codec)
		wantEncodeErr error
		wantDecodeErr error
	}

	gob.Register(sessionData{})

	tests := map[string]testCase{
		"happy_path": {
			hashKey: []byte("hash-key"),
			name:    "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"no_hash_key": {
			wantEncodeErr: ErrHashKeyNotSet,
		},
		"with_serializer": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithSerializer(GobSerializer{}),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"with_serializer_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithSerializer(GobSerializer{}),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
			adjustCodec: func(c *codec) {
				c.serializer = JsonSerializer{}
			},
			wantDecodeErr: ErrDeserializeFailed,
		},
		"with_max_age": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithMaxAge(100),
				withTimestampFn([]int64{0, 99}), // simulate time passing 0 -> 99
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"with_max_age_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithMaxAge(100),
				withTimestampFn([]int64{0, 1000}), // simulate time passing 0 -> 1000
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
			wantDecodeErr: ErrTimestampIsExpired,
		},
		"with_min_age": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithMinAge(100),
				withTimestampFn([]int64{0, 101}), // simulate time passing 0 -> 101
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"with_min_age_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithMinAge(100),
				withTimestampFn([]int64{0, 99}), // simulate time passing 0 -> 99
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
			wantDecodeErr: ErrTimestampIsTooNew,
		},
		"with_max_length_encode_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithMaxLength(10),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
			wantEncodeErr: ErrEncodedLengthTooLong,
		},
		"with_max_length_decode_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{},
			name:    "session-name",
			src: sessionData{
				Value: "session-value",
			},
			adjustCodec: func(c *codec) {
				c.maxLength = 10
			},
			wantDecodeErr: ErrEncodedLengthTooLong,
		},
		"with_hash_fn": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithHashFn(sha512.New),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"with_block_key": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithBlockKey(RandomBytes(16)),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
		"with_block_key_error": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithBlockKey(RandomBytes(1)),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
			wantEncodeErr: ErrCreatingBlockCipher,
		},
		"with_block": {
			hashKey: []byte("hash-key"),
			options: []CodecOption{
				WithBlock(func() cipher.Block {
					b, _ := des.NewCipher(RandomBytes(16))
					return b
				}()),
			},
			name: "session-name",
			src: sessionData{
				Value: "session-value",
			},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := NewCodec(tc.hashKey, tc.options...)
			encoded, err := c.Encode(tc.name, tc.src)
			if tc.wantEncodeErr != nil {
				assert.ErrorIs(t, err, tc.wantEncodeErr)
				return
			} else {
				assert.NoError(t, err)
			}

			if tc.adjustCodec != nil {
				tc.adjustCodec(c.(*codec))
			}

			var dst sessionData
			err = c.Decode(tc.name, encoded, &dst)
			if tc.wantDecodeErr != nil {
				assert.ErrorIs(t, err, tc.wantDecodeErr)
				return
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.src, dst)
		})
	}
}
