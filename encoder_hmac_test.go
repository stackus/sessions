package sessions

import (
	"bytes"
	"fmt"
	"sync"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHMACEncoder(t *testing.T, key []byte, opts ...EncoderOption) *HMACEncoder {
	t.Helper()
	enc, err := NewHMACEncoder(key, opts...)
	require.NoError(t, err)
	return enc
}

func assertInvalidEncoding(t *testing.T, decoded []byte, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Nil(t, decoded)
	assert.True(t, errors.Is(err, ErrInvalidEncoding), "want ErrInvalidEncoding, got %v", err)
}

func TestNewHMACEncoder_KeyValidation(t *testing.T) {
	tests := map[string]struct {
		key     []byte
		wantErr bool
	}{
		"nil":      {key: nil, wantErr: true},
		"empty":    {key: []byte{}, wantErr: true},
		"31 bytes": {key: randomBytes(t, 31), wantErr: true},
		"32 bytes": {key: randomBytes(t, 32), wantErr: false},
		"64 bytes": {key: randomBytes(t, 64), wantErr: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			enc, err := NewHMACEncoder(tc.key)
			if !tc.wantErr {
				require.NoError(t, err)
				assert.NotNil(t, enc)
				return
			}
			require.Error(t, err)
			assert.Nil(t, enc)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
			if len(tc.key) > 0 {
				assert.NotContains(t, err.Error(), string(tc.key))
			}
		})
	}
}

func TestHMACEncoder_RoundTrip(t *testing.T) {
	key := randomBytes(t, 32)
	encoders := map[string]*HMACEncoder{
		"no label": newTestHMACEncoder(t, key),
		"label":    newTestHMACEncoder(t, key, WithEncoderLabel("auth")),
	}
	payloads := map[string][]byte{
		"empty":  {},
		"text":   []byte(`{"user":42}`),
		"binary": {0x00, 0xff, 0x01, 0x80},
	}
	for encName, enc := range encoders {
		for name, data := range payloads {
			t.Run(encName+"/"+name, func(t *testing.T) {
				encoded, err := enc.Encode(data)
				require.NoError(t, err)
				assert.Len(t, encoded, 1+len(data)+32)
				assert.True(t, bytes.Contains(encoded, data), "HMAC must not conceal the payload")

				decoded, err := enc.Decode(encoded)
				require.NoError(t, err)
				assert.Equal(t, data, decoded)
			})
		}
	}
}

func TestHMACEncoder_Decode_Tampering(t *testing.T) {
	enc := newTestHMACEncoder(t, randomBytes(t, 32))
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
		"empty":               {},
		"version only":        encoded[:1],
		"shorter than tag":    encoded[:32],
		"truncated tag":       encoded[:len(encoded)-1],
		"truncated payload":   append(bytes.Clone(encoded[:5]), encoded[len(encoded)-32:]...),
		"extended":            append(bytes.Clone(encoded), 0x00),
		"unsupported version": append([]byte{2}, encoded[1:]...),
	}
	for name, input := range malformed {
		t.Run(name, func(t *testing.T) {
			decoded, err := enc.Decode(input)
			assertInvalidEncoding(t, decoded, err)
		})
	}
}

func TestHMACEncoder_Decode_ForeignKeyOrLabel(t *testing.T) {
	key := randomBytes(t, 32)
	tests := map[string]struct {
		encoder *HMACEncoder
		decoder *HMACEncoder
	}{
		"different key":       {newTestHMACEncoder(t, key), newTestHMACEncoder(t, randomBytes(t, 32))},
		"different label":     {newTestHMACEncoder(t, key, WithEncoderLabel("auth")), newTestHMACEncoder(t, key, WithEncoderLabel("prefs"))},
		"label then no label": {newTestHMACEncoder(t, key, WithEncoderLabel("auth")), newTestHMACEncoder(t, key)},
		"no label then label": {newTestHMACEncoder(t, key), newTestHMACEncoder(t, key, WithEncoderLabel("auth"))},
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

// Without a length prefix, label "ab" + payload "payload" and label "a" +
// payload "bpayload" would produce the same MAC input.
func TestHMACEncoder_LabelBoundaryIsUnambiguous(t *testing.T) {
	key := randomBytes(t, 32)
	encoded, err := newTestHMACEncoder(t, key, WithEncoderLabel("ab")).Encode([]byte("payload"))
	require.NoError(t, err)

	shifted := append([]byte{encoded[0], 'b'}, encoded[1:]...)
	decoded, err := newTestHMACEncoder(t, key, WithEncoderLabel("a")).Decode(shifted)
	assertInvalidEncoding(t, decoded, err)
}

func TestHMACEncoder_EmptyLabelEqualsNoLabel(t *testing.T) {
	key := randomBytes(t, 32)
	encoded, err := newTestHMACEncoder(t, key, WithEncoderLabel("")).Encode([]byte("data"))
	require.NoError(t, err)

	decoded, err := newTestHMACEncoder(t, key).Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decoded)
}

func TestHMACEncoder_KeyIsCopied(t *testing.T) {
	key := randomBytes(t, 32)
	original := bytes.Clone(key)
	enc := newTestHMACEncoder(t, key)

	encoded, err := enc.Encode([]byte("data"))
	require.NoError(t, err)

	for i := range key {
		key[i] = 0
	}
	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decoded)

	fresh, err := newTestHMACEncoder(t, original).Encode([]byte("data"))
	require.NoError(t, err)
	assert.Equal(t, fresh, encoded)
}

func TestHMACEncoder_NoAliasing(t *testing.T) {
	enc := newTestHMACEncoder(t, randomBytes(t, 32))

	input := []byte("session data")
	encoded, err := enc.Encode(input)
	require.NoError(t, err)
	input[0] = 'X'
	decoded, err := enc.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, "session data", string(decoded), "Encode output must not alias its input")

	encoded[1] = 'Y'
	assert.Equal(t, "session data", string(decoded), "Decode output must not alias its input")
}

func TestHMACEncoder_Concurrent(t *testing.T) {
	enc := newTestHMACEncoder(t, randomBytes(t, 32), WithEncoderLabel("auth"))

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
