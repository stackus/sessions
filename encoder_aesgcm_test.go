package sessions

import (
	"bytes"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, fmt.Errorf("entropy unavailable") }

func newTestAESGCMEncoder(t *testing.T, key []byte, opts ...EncoderOption) *AESGCMEncoder {
	t.Helper()
	enc, err := NewAESGCMEncoder(key, opts...)
	require.NoError(t, err)
	return enc
}

func TestNewAESGCMEncoder_KeyValidation(t *testing.T) {
	for _, size := range []int{0, 1, 15, 17, 23, 25, 31, 33, 64} {
		t.Run(fmt.Sprintf("%d bytes rejected", size), func(t *testing.T) {
			enc, err := NewAESGCMEncoder(make([]byte, size))
			require.Error(t, err)
			assert.Nil(t, enc)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
	for _, size := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d bytes accepted", size), func(t *testing.T) {
			enc, err := NewAESGCMEncoder(randomBytes(t, size))
			require.NoError(t, err)
			assert.NotNil(t, enc)
		})
	}
}

func TestAESGCMEncoder_RoundTrip(t *testing.T) {
	payloads := map[string][]byte{
		"empty":  {},
		"text":   []byte(`{"user":42,"secret":"hunter2"}`),
		"binary": {0x00, 0xff, 0x01, 0x80},
	}
	for _, size := range []int{16, 24, 32} {
		key := randomBytes(t, size)
		encoders := map[string]*AESGCMEncoder{
			"no label": newTestAESGCMEncoder(t, key),
			"label":    newTestAESGCMEncoder(t, key, WithEncoderLabel("auth")),
		}
		for encName, enc := range encoders {
			for name, data := range payloads {
				t.Run(fmt.Sprintf("aes-%d/%s/%s", size*8, encName, name), func(t *testing.T) {
					encoded, err := enc.Encode(data)
					require.NoError(t, err)
					assert.Len(t, encoded, 1+12+len(data)+16)
					if len(data) > 0 {
						assert.False(t, bytes.Contains(encoded, data), "plaintext must not appear in the output")
					}

					decoded, err := enc.Decode(encoded)
					require.NoError(t, err)
					assert.Equal(t, data, decoded)
				})
			}
		}
	}
}

func TestAESGCMEncoder_FreshNonces(t *testing.T) {
	enc := newTestAESGCMEncoder(t, randomBytes(t, 32))
	data := []byte("same input")

	seen := make(map[string]bool)
	for range 100 {
		encoded, err := enc.Encode(data)
		require.NoError(t, err)
		nonce := string(encoded[1:13])
		assert.False(t, seen[nonce], "nonce reused")
		seen[nonce] = true
	}
}

func TestAESGCMEncoder_Decode_Tampering(t *testing.T) {
	enc := newTestAESGCMEncoder(t, randomBytes(t, 32))
	encoded, err := enc.Encode([]byte("user=42;admin=false"))
	require.NoError(t, err)

	for i := range encoded {
		t.Run(fmt.Sprintf("flip byte %d", i), func(t *testing.T) {
			tampered := bytes.Clone(encoded)
			tampered[i] ^= 0x01
			decoded, err := enc.Decode(tampered)
			assertInvalidEncoding(t, decoded, err)
		})
	}

	malformed := map[string][]byte{
		"empty":                  {},
		"version only":           encoded[:1],
		"version and nonce":      encoded[:13],
		"shorter than minimum":   encoded[:1+12+15],
		"truncated":              encoded[:len(encoded)-1],
		"extended":               append(bytes.Clone(encoded), 0x00),
		"unsupported version":    append([]byte{2}, encoded[1:]...),
		"minimum length garbage": make([]byte, 1+12+16),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			decoded, err := enc.Decode(input)
			assertInvalidEncoding(t, decoded, err)
		})
	}
}

func TestAESGCMEncoder_Decode_ForeignKeyOrLabel(t *testing.T) {
	key := randomBytes(t, 32)
	tests := map[string]struct {
		encoder *AESGCMEncoder
		decoder *AESGCMEncoder
	}{
		"different key":       {newTestAESGCMEncoder(t, key), newTestAESGCMEncoder(t, randomBytes(t, 32))},
		"different key size":  {newTestAESGCMEncoder(t, key), newTestAESGCMEncoder(t, key[:16])},
		"different label":     {newTestAESGCMEncoder(t, key, WithEncoderLabel("auth")), newTestAESGCMEncoder(t, key, WithEncoderLabel("prefs"))},
		"label then no label": {newTestAESGCMEncoder(t, key, WithEncoderLabel("auth")), newTestAESGCMEncoder(t, key)},
		"no label then label": {newTestAESGCMEncoder(t, key), newTestAESGCMEncoder(t, key, WithEncoderLabel("auth"))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := tc.encoder.Encode([]byte("payload"))
			require.NoError(t, err)

			decoded, err := tc.decoder.Decode(encoded)
			assertInvalidEncoding(t, decoded, err)
		})
	}
}

func TestAESGCMEncoder_RandomFailureIsOperational(t *testing.T) {
	enc := newTestAESGCMEncoder(t, randomBytes(t, 32))
	enc.rand = failingReader{}

	encoded, err := enc.Encode([]byte("data"))
	require.Error(t, err)
	assert.Nil(t, encoded)
	assert.False(t, errors.Is(err, ErrInvalidEncoding))
	assert.False(t, IsNoSession(err))
	assert.Equal(t, http.StatusInternalServerError, errors.HTTPCode(err))
}

func TestAESGCMEncoder_KeyNotRetained(t *testing.T) {
	key := randomBytes(t, 32)
	enc := newTestAESGCMEncoder(t, key)
	encoded, err := enc.Encode([]byte("data"))
	require.NoError(t, err)

	for i := range key {
		key[i] = 0
	}
	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decoded)
}

func TestAESGCMEncoder_NoAliasing(t *testing.T) {
	enc := newTestAESGCMEncoder(t, randomBytes(t, 32))

	input := []byte("session data")
	encoded, err := enc.Encode(input)
	require.NoError(t, err)
	input[0] = 'X'

	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, "session data", string(decoded), "Encode output must not alias its input")

	for i := range encoded {
		encoded[i] = 0
	}
	assert.Equal(t, "session data", string(decoded), "Decode output must not alias its input")
}

func TestAESGCMEncoder_Concurrent(t *testing.T) {
	enc := newTestAESGCMEncoder(t, randomBytes(t, 32), WithEncoderLabel("auth"))

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() {
			for j := range 100 {
				data := fmt.Appendf(nil, "worker %d item %d", i, j)
				encoded, err := enc.Encode(data)
				if !assert.NoError(t, err) {
					return
				}
				decoded, err := enc.Decode(encoded)
				if !assert.NoError(t, err) {
					return
				}
				assert.Equal(t, data, decoded)
			}
		})
	}
	wg.Wait()
}
