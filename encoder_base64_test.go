package sessions

import (
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBase64Encoder_RoundTrip(t *testing.T) {
	tests := map[string][]byte{
		"empty":  {},
		"text":   []byte(`{"user":42}`),
		"binary": {0x00, 0xff, 0xfe, 0x01, 0x80, 0x7f},
	}
	enc := NewBase64Encoder()
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := enc.Encode(data)
			require.NoError(t, err)

			decoded, err := enc.Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, data, decoded)
		})
	}
}

func TestBase64Encoder_Encode_URLSafeUnpadded(t *testing.T) {
	encoded, err := NewBase64Encoder().Encode([]byte{0xfb, 0xff})
	require.NoError(t, err)
	assert.Equal(t, "-_8", string(encoded))
}

func TestBase64Encoder_Decode_Invalid(t *testing.T) {
	tests := map[string]string{
		"invalid character":   "not base64!",
		"padding":             "-_8=",
		"standard alphabet":   "+/8",
		"impossible length":   "a",
		"non-zero extra bits": "-_9",
	}
	enc := NewBase64Encoder()
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			decoded, err := enc.Decode([]byte(input))
			require.Error(t, err)
			assert.Nil(t, decoded)
			assert.True(t, errors.Is(err, ErrInvalidEncoding))
			assert.Equal(t, "SESSION_INVALID_ENCODING", errors.TypeCode(err))
		})
	}
}

func TestBase64Encoder_NoAliasing(t *testing.T) {
	enc := NewBase64Encoder()

	input := []byte("session data")
	encoded, err := enc.Encode(input)
	require.NoError(t, err)
	want := string(encoded)
	input[0] = 'X'
	assert.Equal(t, want, string(encoded), "Encode output must not alias its input")

	encodedInput := []byte(want)
	decoded, err := enc.Decode(encodedInput)
	require.NoError(t, err)
	encodedInput[0] = 'A'
	assert.Equal(t, "session data", string(decoded), "Decode output must not alias its input")
}
