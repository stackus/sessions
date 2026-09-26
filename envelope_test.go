package sessions

import (
	"strings"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type envelopeTestData struct {
	UserID int               `json:"user_id"`
	Roles  []string          `json:"roles"`
	Prefs  map[string]string `json:"prefs"`
}

var (
	envCreated = time.Unix(1_700_000_000, 0)
	envExpires = envCreated.Add(defaultLifetime)
	envMeta    = envelopeMeta{CreatedAt: envCreated, ExpiresAt: envExpires}
)

func mustMarshalEnvelope[T any](t *testing.T, values T) []byte {
	t.Helper()
	data, err := marshalEnvelope(values, envMeta, defaultMaxPayloadSize)
	require.NoError(t, err)
	return data
}

func TestEnvelope_RoundTrip(t *testing.T) {
	values := envelopeTestData{UserID: 42, Roles: []string{"admin"}, Prefs: map[string]string{"theme": "dark"}}
	data := mustMarshalEnvelope(t, values)

	got, meta, err := unmarshalEnvelope[envelopeTestData](data, envCreated.Add(time.Hour), defaultMaxPayloadSize)
	require.NoError(t, err)
	assert.Equal(t, values, got)
	assert.True(t, meta.CreatedAt.Equal(envCreated))
	assert.True(t, meta.ExpiresAt.Equal(envExpires))
}

func TestEnvelope_ZeroValueRoundTrip(t *testing.T) {
	data := mustMarshalEnvelope(t, envelopeTestData{})
	got, _, err := unmarshalEnvelope[envelopeTestData](data, envCreated, defaultMaxPayloadSize)
	require.NoError(t, err)
	assert.Equal(t, envelopeTestData{}, got)
}

func TestEnvelope_CompactFormat(t *testing.T) {
	data := mustMarshalEnvelope(t, map[string]int{"n": 1})
	assert.Equal(t, `{"v":1,"c":1700000000,"e":1702592000,"d":{"n":1}}`, string(data))
}

func TestEnvelope_TimestampsHaveSecondPrecision(t *testing.T) {
	meta := envelopeMeta{
		CreatedAt: envCreated.Add(900 * time.Millisecond),
		ExpiresAt: envExpires.Add(900 * time.Millisecond),
	}
	data, err := marshalEnvelope(1, meta, defaultMaxPayloadSize)
	require.NoError(t, err)

	_, got, err := unmarshalEnvelope[int](data, envCreated, defaultMaxPayloadSize)
	require.NoError(t, err)
	assert.True(t, got.CreatedAt.Equal(envCreated))
	assert.True(t, got.ExpiresAt.Equal(envExpires))
}

func TestMarshalEnvelope_OperationalFailures(t *testing.T) {
	tests := map[string]func() ([]byte, error){
		"unserializable values": func() ([]byte, error) {
			return marshalEnvelope(func() {}, envMeta, defaultMaxPayloadSize)
		},
		"expiry before creation": func() ([]byte, error) {
			return marshalEnvelope(1, envelopeMeta{CreatedAt: envExpires, ExpiresAt: envCreated}, defaultMaxPayloadSize)
		},
		"expiry equals creation": func() ([]byte, error) {
			return marshalEnvelope(1, envelopeMeta{CreatedAt: envCreated, ExpiresAt: envCreated}, defaultMaxPayloadSize)
		},
		"zero timestamps": func() ([]byte, error) {
			return marshalEnvelope(1, envelopeMeta{}, defaultMaxPayloadSize)
		},
		"over payload limit": func() ([]byte, error) {
			return marshalEnvelope(strings.Repeat("x", 100), envMeta, 64)
		},
	}
	for name, marshal := range tests {
		t.Run(name, func(t *testing.T) {
			data, err := marshal()
			require.Error(t, err)
			assert.Nil(t, data)
			assert.False(t, IsNoSession(err))
			assert.Equal(t, "INTERNAL", errors.TypeCode(err))
		})
	}
}

func TestUnmarshalEnvelope_Rejections(t *testing.T) {
	valid := string(mustMarshalEnvelope(t, envelopeTestData{UserID: 42}))
	now := envCreated.Add(time.Hour)

	tests := map[string]struct {
		data       string
		now        time.Time
		maxPayload int
		wantErr    error
		wantCode   string
		wantUnavl  bool
	}{
		"oversized": {
			data: valid, maxPayload: len(valid) - 1,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"empty":         {data: "", wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true},
		"garbage":       {data: "not json", wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true},
		"json array":    {data: "[1,2]", wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true},
		"truncated":     {data: valid[:len(valid)-5], wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true},
		"trailing data": {data: valid + `{}`, wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true},
		"unknown field": {
			data:    `{"v":1,"c":1700000000,"e":1702592000,"d":{},"x":1}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"unknown version": {
			data:    `{"v":2,"c":1700000000,"e":1702592000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"missing version": {
			data:    `{"c":1700000000,"e":1702592000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"missing created": {
			data:    `{"v":1,"e":1702592000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"missing expires": {
			data:    `{"v":1,"c":1700000000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"expiry before creation": {
			data:    `{"v":1,"c":1702592000,"e":1700000000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"expiry equals creation": {
			data:    `{"v":1,"c":1700000000,"e":1700000000,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"missing data": {
			data:    `{"v":1,"c":1700000000,"e":1702592000}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"timestamp overflow": {
			data:    `{"v":1,"c":1700000000,"e":99999999999999999999,"d":{}}`,
			wantErr: ErrInvalidSession, wantCode: "SESSION_INVALID", wantUnavl: true,
		},
		"expired": {
			data: valid, now: envExpires.Add(time.Second),
			wantErr: ErrSessionExpired, wantCode: "SESSION_EXPIRED", wantUnavl: true,
		},
		"exactly at expiry": {
			data: valid, now: envExpires,
			wantErr: ErrSessionExpired, wantCode: "SESSION_EXPIRED", wantUnavl: true,
		},
		"values type mismatch": {
			data:    `{"v":1,"c":1700000000,"e":1702592000,"d":{"user_id":"not a number"}}`,
			wantErr: errors.ErrInternal, wantCode: "INTERNAL", wantUnavl: false,
		},
		"values wrong shape": {
			data:    `{"v":1,"c":1700000000,"e":1702592000,"d":[1,2,3]}`,
			wantErr: errors.ErrInternal, wantCode: "INTERNAL", wantUnavl: false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.now.IsZero() {
				tc.now = now
			}
			if tc.maxPayload == 0 {
				tc.maxPayload = defaultMaxPayloadSize
			}
			got, meta, err := unmarshalEnvelope[envelopeTestData](([]byte)(tc.data), tc.now, tc.maxPayload)
			require.Error(t, err)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
			assert.Equal(t, tc.wantCode, errors.TypeCode(err))
			assert.Equal(t, tc.wantUnavl, IsNoSession(err))
			assert.Equal(t, envelopeTestData{}, got, "no partially decoded values")
			assert.Equal(t, envelopeMeta{}, meta)
		})
	}
}

func TestUnmarshalEnvelope_UnknownValueFieldsAreIgnored(t *testing.T) {
	// Removing a field from T must not invalidate existing sessions.
	data := `{"v":1,"c":1700000000,"e":1702592000,"d":{"user_id":7,"removed_field":true}}`
	got, _, err := unmarshalEnvelope[envelopeTestData]([]byte(data), envCreated, defaultMaxPayloadSize)
	require.NoError(t, err)
	assert.Equal(t, 7, got.UserID)
}

func TestUnmarshalEnvelope_PartialDecodeReturnsZero(t *testing.T) {
	// user_id decodes before roles fails; the partial value must not leak.
	data := `{"v":1,"c":1700000000,"e":1702592000,"d":{"user_id":7,"roles":"not a list"}}`
	got, _, err := unmarshalEnvelope[envelopeTestData]([]byte(data), envCreated, defaultMaxPayloadSize)
	require.Error(t, err)
	assert.Equal(t, envelopeTestData{}, got)
}
