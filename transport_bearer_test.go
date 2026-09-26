package sessions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestBearerTransport(t *testing.T, opts ...BearerTransportOption) *BearerTransport {
	t.Helper()
	transport, err := NewBearerTransport(opts...)
	require.NoError(t, err)
	return transport
}

func requestWithAuthorization(values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, v := range values {
		r.Header.Add("Authorization", v)
	}
	return r
}

func TestNewBearerTransport_InvalidConfig(t *testing.T) {
	tests := map[string][]BearerTransportOption{
		"empty header":         {BearerTransportTokenHeader("")},
		"header with space":    {BearerTransportTokenHeader("Session Token")},
		"header with colon":    {BearerTransportTokenHeader("Session:Token")},
		"authorization header": {BearerTransportTokenHeader("authorization")},
		"zero size":            {BearerTransportMaxCredentialSize(0)},
		"negative size":        {BearerTransportMaxCredentialSize(-1)},
	}
	for name, opts := range tests {
		t.Run(name, func(t *testing.T) {
			transport, err := NewBearerTransport(opts...)
			require.Error(t, err)
			assert.Nil(t, transport)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
}

func TestBearerTransport_Read(t *testing.T) {
	transport := newTestBearerTransport(t, BearerTransportMaxCredentialSize(16))
	tests := map[string]struct {
		values  []string
		want    string
		wantErr *errors.Kind
	}{
		"missing":            {values: nil, wantErr: ErrNoCredential},
		"valid":              {values: []string{"Bearer abc123"}, want: "abc123"},
		"lowercase scheme":   {values: []string{"bearer abc123"}, want: "abc123"},
		"uppercase scheme":   {values: []string{"BEARER abc123"}, want: "abc123"},
		"extra spaces":       {values: []string{"Bearer   abc123"}, want: "abc123"},
		"token68 characters": {values: []string{"Bearer aZ09-._~+/=="}, want: "aZ09-._~+/=="},
		"padded token":       {values: []string{"Bearer abc123=="}, want: "abc123=="},
		"base64url token":    {values: []string{"Bearer abc_DEF-123"}, want: "abc_DEF-123"},
		"at size limit":      {values: []string{"Bearer " + strings.Repeat("x", 16)}, want: strings.Repeat("x", 16)},
		"basic scheme":       {values: []string{"Basic dXNlcjpwYXNz"}, wantErr: ErrNoCredential},
		"scheme prefix":      {values: []string{"Bearerabc123"}, wantErr: ErrNoCredential},
		"multiple headers":   {values: []string{"Bearer first", "Bearer second"}, wantErr: ErrInvalidSession},
		"scheme only":        {values: []string{"Bearer"}, wantErr: ErrInvalidSession},
		"scheme and space":   {values: []string{"Bearer "}, wantErr: ErrInvalidSession},
		"two tokens":         {values: []string{"Bearer abc123 def456"}, wantErr: ErrInvalidSession},
		"comma list":         {values: []string{"Bearer abc123, Bearer def456"}, wantErr: ErrInvalidSession},
		"invalid character":  {values: []string{"Bearer abc!123"}, wantErr: ErrInvalidSession},
		"only padding":       {values: []string{"Bearer =="}, wantErr: ErrInvalidSession},
		"padding in middle":  {values: []string{"Bearer ab=c"}, wantErr: ErrInvalidSession},
		"oversized":          {values: []string{"Bearer " + strings.Repeat("x", 17)}, wantErr: ErrInvalidSession},
		"auth-param syntax":  {values: []string{`Bearer realm="x"`}, wantErr: ErrInvalidSession},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			credential, err := transport.Read(requestWithAuthorization(tc.values...))
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.want, credential)
				return
			}
			assert.Empty(t, credential)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
			for _, secret := range []string{"abc123", "first", "second", "dXNlcjpwYXNz", strings.Repeat("x", 17)} {
				assert.NotContains(t, err.Error(), secret, "credential must not appear in the error")
			}
		})
	}
}

func TestBearerTransport_WriteClear(t *testing.T) {
	tests := map[string]struct {
		opts         []BearerTransportOption
		tokenHeader  string
		actionHeader string
	}{
		"default header": {tokenHeader: "Session-Token", actionHeader: "Session-Token-Action"},
		"custom header": {
			opts:         []BearerTransportOption{BearerTransportTokenHeader("app-token")},
			tokenHeader:  "App-Token",
			actionHeader: "App-Token-Action",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			transport := newTestBearerTransport(t, tc.opts...)
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			rec := httptest.NewRecorder()
			require.NoError(t, transport.Write(rec, r, "abc_DEF-123", testTransportParams()))
			assert.Equal(t, "abc_DEF-123", rec.Header().Get(tc.tokenHeader))
			assert.Empty(t, rec.Header().Values(tc.actionHeader))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
			assert.Empty(t, rec.Header().Values("Authorization"), "Authorization is never a response header")

			rec = httptest.NewRecorder()
			require.NoError(t, transport.Clear(rec, r))
			assert.Equal(t, "clear", rec.Header().Get(tc.actionHeader))
			assert.Empty(t, rec.Header().Values(tc.tokenHeader))
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		})
	}
}

func TestBearerTransport_LastOperationWins(t *testing.T) {
	transport := newTestBearerTransport(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Delete, then a new session saved in the same response.
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Clear(rec, r))
	require.NoError(t, transport.Write(rec, r, "new-token", testTransportParams()))
	assert.Equal(t, []string{"new-token"}, rec.Header().Values("Session-Token"))
	assert.Empty(t, rec.Header().Values("Session-Token-Action"))

	// Issued, then cleared in the same response.
	rec = httptest.NewRecorder()
	require.NoError(t, transport.Write(rec, r, "token", testTransportParams()))
	require.NoError(t, transport.Clear(rec, r))
	assert.Empty(t, rec.Header().Values("Session-Token"))
	assert.Equal(t, []string{"clear"}, rec.Header().Values("Session-Token-Action"))
}

func TestBearerTransport_Write_Refused(t *testing.T) {
	transport := newTestBearerTransport(t, BearerTransportMaxCredentialSize(16))
	tests := map[string]string{
		"empty":        "",
		"oversized":    strings.Repeat("x", 17),
		"space":        "has space",
		"newline":      "abc\r\nX-Injected: 1",
		"only padding": "==",
		"comma":        "a,b",
	}
	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), credential, testTransportParams())
			require.Error(t, err)
			assert.False(t, IsNoSession(err))
			assert.Equal(t, "INTERNAL", errors.TypeCode(err))
			assert.Empty(t, rec.Header(), "nothing written")
			if len(credential) > 3 {
				assert.NotContains(t, err.Error(), credential)
			}
		})
	}
}

func TestBearerTransport_WriteThenRead(t *testing.T) {
	transport := newTestBearerTransport(t)
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), "abc_DEF-123", testTransportParams()))

	credential, err := transport.Read(requestWithAuthorization("Bearer " + rec.Header().Get("Session-Token")))
	require.NoError(t, err)
	assert.Equal(t, "abc_DEF-123", credential)
}
