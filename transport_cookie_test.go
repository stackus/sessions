package sessions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setCookies returns the cookies set on rec.
func setCookies(t *testing.T, rec *httptest.ResponseRecorder) []*http.Cookie {
	t.Helper()
	var cookies []*http.Cookie
	for _, line := range rec.Header().Values("Set-Cookie") {
		c, err := http.ParseSetCookie(line)
		require.NoError(t, err)
		cookies = append(cookies, c)
	}
	return cookies
}

func requestWithCookieHeader(header string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if header != "" {
		r.Header.Set("Cookie", header)
	}
	return r
}

func newTestCookieTransport(t *testing.T, name string, opts ...CookieTransportOption) *CookieTransport {
	t.Helper()
	transport, err := NewCookieTransport(name, opts...)
	require.NoError(t, err)
	return transport
}

func TestNewCookieTransport_InvalidConfig(t *testing.T) {
	tests := map[string]struct {
		name string
		opts []CookieTransportOption
	}{
		"empty name":               {name: ""},
		"invalid name":             {name: "bad name"},
		"invalid path":             {name: "session", opts: []CookieTransportOption{CookieTransportPath("/a;b")}},
		"invalid domain":           {name: "session", opts: []CookieTransportOption{CookieTransportDomain("bad domain")}},
		"zero credential size":     {name: "session", opts: []CookieTransportOption{CookieTransportMaxCredentialSize(0)}},
		"partitioned not secure":   {name: "session", opts: []CookieTransportOption{CookieTransportPartitioned(true), CookieTransportSecure(false)}},
		"samesite none not secure": {name: "session", opts: []CookieTransportOption{CookieTransportSameSite(http.SameSiteNoneMode), CookieTransportSecure(false)}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			transport, err := NewCookieTransport(tc.name, tc.opts...)
			require.Error(t, err)
			assert.Nil(t, transport)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
}

func TestCookieTransport_Read(t *testing.T) {
	transport := newTestCookieTransport(t, "session", CookieTransportMaxCredentialSize(16))
	tests := map[string]struct {
		header    string
		want      string
		wantErr   *errors.Kind
		wantInMsg string
	}{
		"missing":             {header: "", wantErr: ErrNoCredential},
		"other cookies only":  {header: "theme=dark; lang=en", wantErr: ErrNoCredential},
		"single":              {header: "theme=dark; session=abc123", want: "abc123"},
		"quoted":              {header: `session="abc123"`, want: "abc123"},
		"duplicate":           {header: "session=first; session=second", wantErr: ErrInvalidSession},
		"empty":               {header: "session=", wantErr: ErrInvalidSession},
		"oversized":           {header: "session=" + strings.Repeat("x", 17), wantErr: ErrInvalidSession},
		"at limit":            {header: "session=" + strings.Repeat("x", 16), want: strings.Repeat("x", 16)},
		"invalid value bytes": {header: "session=a\\b", wantErr: ErrNoCredential},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			credential, err := transport.Read(requestWithCookieHeader(tc.header))
			if tc.wantErr == nil {
				require.NoError(t, err)
				assert.Equal(t, tc.want, credential)
				return
			}
			assert.Empty(t, credential)
			assert.True(t, errors.Is(err, tc.wantErr), "want %v, got %v", tc.wantErr, err)
			for _, value := range []string{"first", "second", "abc123", strings.Repeat("x", 17)} {
				assert.NotContains(t, err.Error(), value, "credential must not appear in the error")
			}
		})
	}
}

func TestCookieTransport_Write_Defaults(t *testing.T) {
	transport := newTestCookieTransport(t, "session")
	rec := httptest.NewRecorder()

	now := time.Unix(1_750_000_000, 0)
	transport.now = func() time.Time { return now }
	expires := now.Add(90*time.Minute + 500*time.Millisecond)
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), "credential-1", TransportParams{ExpiresAt: expires}))

	cookies := setCookies(t, rec)
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "session", c.Name)
	assert.Equal(t, "credential-1", c.Value)
	assert.Equal(t, "/", c.Path)
	assert.Empty(t, c.Domain)
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, c.SameSite)
	assert.False(t, c.Partitioned)
	assert.Equal(t, 90*60+1, c.MaxAge, "Max-Age rounds the time to the session expiry up")
	assert.True(t, c.Expires.Equal(expires.Truncate(time.Second)), "Expires is the session expiry")
}

func TestCookieTransport_Write_ExpiredSessionNeverDeletes(t *testing.T) {
	transport := newTestCookieTransport(t, "session")
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), "cred", TransportParams{ExpiresAt: time.Now().Add(-time.Minute)}))

	cookies := setCookies(t, rec)
	require.Len(t, cookies, 1)
	assert.Equal(t, 1, cookies[0].MaxAge, "Max-Age never reaches zero, which would delete the cookie")
}

func TestCookieTransport_Write_Options(t *testing.T) {
	transport := newTestCookieTransport(t, "app",
		CookieTransportPath("/app"),
		CookieTransportDomain("example.com"),
		CookieTransportHTTPOnly(false),
		CookieTransportSameSite(http.SameSiteStrictMode),
		CookieTransportPartitioned(true),
	)
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), "cred", testTransportParams()))

	cookies := setCookies(t, rec)
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "app", c.Name)
	assert.Equal(t, "/app", c.Path)
	assert.Equal(t, "example.com", c.Domain)
	assert.True(t, c.Secure)
	assert.False(t, c.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, c.SameSite)
	assert.True(t, c.Partitioned)
}

func TestCookieTransport_Write_LocalDevelopment(t *testing.T) {
	transport := newTestCookieTransport(t, "session", CookieTransportSecure(false), CookieTransportPersistent(false))
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), "cred", testTransportParams()))

	cookies := setCookies(t, rec)
	require.Len(t, cookies, 1)
	assert.False(t, cookies[0].Secure)
	assert.Zero(t, cookies[0].MaxAge, "browser-session cookie")
	assert.True(t, cookies[0].Expires.IsZero())
}

func TestCookieTransport_Write_Refused(t *testing.T) {
	transport := newTestCookieTransport(t, "session", CookieTransportMaxCredentialSize(16))
	tests := map[string]string{
		"empty":     "",
		"oversized": strings.Repeat("x", 17),
		"space":     "has space",
		"comma":     "a,b",
		"backslash": `a\b`,
		"non-ascii": "caf\u00e9",
		"semicolon": "a;b",
		"quote":     `a"b`,
	}
	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			err := transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), credential, testTransportParams())
			require.Error(t, err)
			assert.False(t, IsNoSession(err))
			assert.Equal(t, "INTERNAL", errors.TypeCode(err))
			assert.Empty(t, rec.Header().Values("Set-Cookie"), "nothing written")
			if len(credential) > 3 {
				assert.NotContains(t, err.Error(), credential)
			}
		})
	}
}

func TestCookieTransport_Clear(t *testing.T) {
	transport := newTestCookieTransport(t, "app",
		CookieTransportPath("/app"),
		CookieTransportDomain("example.com"),
		CookieTransportPartitioned(true),
	)
	rec := httptest.NewRecorder()
	require.NoError(t, transport.Clear(rec, httptest.NewRequest(http.MethodGet, "/", nil)))

	cookies := setCookies(t, rec)
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "app", c.Name, "same name")
	assert.Equal(t, "/app", c.Path, "same path")
	assert.Equal(t, "example.com", c.Domain, "same domain")
	assert.Empty(t, c.Value)
	assert.Less(t, c.MaxAge, 0, "Max-Age=0 on the wire")
	assert.True(t, c.Expires.Before(time.Unix(2, 0)), "expiry in the past")
	assert.True(t, c.Secure)
	assert.True(t, c.HttpOnly)
	assert.True(t, c.Partitioned)
	assert.Contains(t, rec.Header().Get("Set-Cookie"), "Max-Age=0")
}

func TestCookieTransport_WriteThenRead(t *testing.T) {
	transport := newTestCookieTransport(t, "session")
	rec := httptest.NewRecorder()
	credential := "abc_DEF-123"
	require.NoError(t, transport.Write(rec, httptest.NewRequest(http.MethodGet, "/", nil), credential, testTransportParams()))

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range setCookies(t, rec) {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	got, err := transport.Read(r)
	require.NoError(t, err)
	assert.Equal(t, credential, got)
}
