package sessions

import (
	"net/http"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubEncoder returns fixed errors and counts calls.
type stubEncoder struct {
	encodeErr   error
	decodeErr   error
	decodeCalls int
}

func (s *stubEncoder) Encode(data []byte) ([]byte, error) {
	if s.encodeErr != nil {
		return nil, s.encodeErr
	}
	return append([]byte("stub:"), data...), nil
}

func (s *stubEncoder) Decode(data []byte) ([]byte, error) {
	s.decodeCalls++
	if s.decodeErr != nil {
		return nil, s.decodeErr
	}
	return data, nil
}

func newTestRotatingEncoder(t *testing.T, current Encoder, previous ...Encoder) *RotatingEncoder {
	t.Helper()
	enc, err := NewRotatingEncoder(current, previous...)
	require.NoError(t, err)
	return enc
}

func TestNewRotatingEncoder_NilEncoders(t *testing.T) {
	hmacEnc := newTestHMACEncoder(t, randomBytes(t, 32))
	tests := map[string]struct {
		current  Encoder
		previous []Encoder
	}{
		"nil current":  {current: nil},
		"nil previous": {current: hmacEnc, previous: []Encoder{hmacEnc, nil}},
		"typed nil":    {current: hmacEnc, previous: []Encoder{(*HMACEncoder)(nil)}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			enc, err := NewRotatingEncoder(tc.current, tc.previous...)
			require.Error(t, err)
			assert.Nil(t, enc)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
}

func TestRotatingEncoder_EncodesWithCurrent(t *testing.T) {
	current := newTestHMACEncoder(t, randomBytes(t, 32))
	old := newTestHMACEncoder(t, randomBytes(t, 32))
	enc := newTestRotatingEncoder(t, current, old)

	encoded, err := enc.Encode([]byte("data"))
	require.NoError(t, err)

	decoded, err := current.Decode(encoded)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decoded)

	_, err = old.Decode(encoded)
	assert.True(t, errors.Is(err, ErrInvalidEncoding), "must not encode with a previous encoder")
}

func TestRotatingEncoder_EncodeNeverFallsBack(t *testing.T) {
	encodeErr := errors.ErrInternal.Msg("current encoder broken")
	previous := newTestHMACEncoder(t, randomBytes(t, 32))
	enc := newTestRotatingEncoder(t, &stubEncoder{encodeErr: encodeErr}, previous)

	encoded, err := enc.Encode([]byte("data"))
	assert.Nil(t, encoded)
	assert.ErrorIs(t, err, encodeErr)
}

func TestRotatingEncoder_DecodeWithRefresh(t *testing.T) {
	newest := newTestAESGCMEncoder(t, randomBytes(t, 32))
	older := newTestAESGCMEncoder(t, randomBytes(t, 32))
	oldest := newTestHMACEncoder(t, randomBytes(t, 32))
	enc := newTestRotatingEncoder(t, newest, older, oldest)

	tests := map[string]struct {
		producer    Encoder
		wantRefresh bool
	}{
		"current key":  {producer: newest, wantRefresh: false},
		"previous key": {producer: older, wantRefresh: true},
		"oldest key":   {producer: oldest, wantRefresh: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			encoded, err := tc.producer.Encode([]byte("data"))
			require.NoError(t, err)

			decoded, refresh, err := enc.DecodeWithRefresh(encoded)
			require.NoError(t, err)
			assert.Equal(t, []byte("data"), decoded)
			assert.Equal(t, tc.wantRefresh, refresh)

			decoded, err = enc.Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, []byte("data"), decoded)
		})
	}
}

func TestRotatingEncoder_AllRejected(t *testing.T) {
	enc := newTestRotatingEncoder(t,
		newTestHMACEncoder(t, randomBytes(t, 32)),
		newTestAESGCMEncoder(t, randomBytes(t, 32)),
	)
	foreign, err := newTestHMACEncoder(t, randomBytes(t, 32)).Encode([]byte("data"))
	require.NoError(t, err)

	decoded, refresh, err := enc.DecodeWithRefresh(foreign)
	assertInvalidEncoding(t, decoded, err)
	assert.False(t, refresh)
	assert.Equal(t, "SESSION_INVALID_ENCODING", errors.TypeCode(err))

	decoded, err = enc.Decode(foreign)
	assertInvalidEncoding(t, decoded, err)
}

func TestRotatingEncoder_OperationalErrorsStopDecoding(t *testing.T) {
	operational := errors.ErrInternal.Msg("key service unavailable")
	tests := map[string]func(failing, fallback Encoder) []Encoder{
		"current fails": func(failing, fallback Encoder) []Encoder {
			return []Encoder{failing, fallback}
		},
		"previous fails": func(failing, fallback Encoder) []Encoder {
			return []Encoder{&stubEncoder{decodeErr: ErrInvalidEncoding.Msg("not mine")}, failing, fallback}
		},
	}
	for name, chain := range tests {
		t.Run(name, func(t *testing.T) {
			fallback := &stubEncoder{}
			encoders := chain(&stubEncoder{decodeErr: operational}, fallback)
			enc := newTestRotatingEncoder(t, encoders[0], encoders[1:]...)

			decoded, refresh, err := enc.DecodeWithRefresh([]byte("data"))
			assert.Nil(t, decoded)
			assert.False(t, refresh)
			assert.ErrorIs(t, err, operational)
			assert.False(t, errors.Is(err, ErrInvalidEncoding))
			assert.Equal(t, http.StatusInternalServerError, errors.HTTPCode(err))
			assert.Zero(t, fallback.decodeCalls, "must not try later encoders after an operational error")
		})
	}
}

func TestRotatingEncoder_NestedRefreshPropagates(t *testing.T) {
	newest := newTestHMACEncoder(t, randomBytes(t, 32))
	older := newTestHMACEncoder(t, randomBytes(t, 32))
	inner := newTestRotatingEncoder(t, newest, older)
	outer := newTestRotatingEncoder(t, inner)

	fromOlder, err := older.Encode([]byte("data"))
	require.NoError(t, err)
	decoded, refresh, err := outer.DecodeWithRefresh(fromOlder)
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), decoded)
	assert.True(t, refresh, "refresh reported by the current (nested) encoder must propagate")

	fromNewest, err := newest.Encode([]byte("data"))
	require.NoError(t, err)
	_, refresh, err = outer.DecodeWithRefresh(fromNewest)
	require.NoError(t, err)
	assert.False(t, refresh)
}
