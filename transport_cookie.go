package sessions

import (
	"fmt"
	"net/http"
	"time"

	"github.com/stackus/errors"
)

const (
	cookieDefaultMaxCredentialSize = 4096
)

// CookieTransport carries the session credential in an HTTP cookie.
//
// Defaults: Path "/", no Domain, Secure, HttpOnly, SameSite=Lax, not
// Partitioned, persistent, and a maximum credential size of 4096 bytes.
//
// Secure is on by default, so browsers only send the cookie over HTTPS. For
// local development over plain HTTP, disable it explicitly with
// CookieTransportSecure(false). The transport never inspects forwarded headers
// to decide this.
//
// A persistent cookie expires together with the session it carries: the
// manager passes the session's expiry to every Write, including after
// Session.Extend.
type CookieTransport struct {
	name              string
	path              string
	domain            string
	secure            bool
	httpOnly          bool
	sameSite          http.SameSite
	partitioned       bool
	persistent        bool
	maxCredentialSize int
	now               func() time.Time
}

var _ Transport = (*CookieTransport)(nil)

// CookieTransportOption configures a CookieTransport.
type CookieTransportOption func(*CookieTransport)

// CookieTransportPath sets the cookie's Path attribute. The default is "/".
func CookieTransportPath(path string) CookieTransportOption {
	return func(t *CookieTransport) { t.path = path }
}

// CookieTransportDomain sets the cookie's Domain attribute. The default is no
// Domain, which limits the cookie to the exact host.
func CookieTransportDomain(domain string) CookieTransportOption {
	return func(t *CookieTransport) { t.domain = domain }
}

// CookieTransportSecure sets the Secure attribute. The default is true;
// disable it only for local development over plain HTTP.
func CookieTransportSecure(secure bool) CookieTransportOption {
	return func(t *CookieTransport) { t.secure = secure }
}

// CookieTransportHTTPOnly sets the HttpOnly attribute. The default is true.
func CookieTransportHTTPOnly(httpOnly bool) CookieTransportOption {
	return func(t *CookieTransport) { t.httpOnly = httpOnly }
}

// CookieTransportSameSite sets the SameSite attribute. The default is
// http.SameSiteLaxMode. http.SameSiteNoneMode requires Secure.
func CookieTransportSameSite(sameSite http.SameSite) CookieTransportOption {
	return func(t *CookieTransport) { t.sameSite = sameSite }
}

// CookieTransportPartitioned sets the Partitioned attribute. The default is
// false. Partitioned requires Secure.
func CookieTransportPartitioned(partitioned bool) CookieTransportOption {
	return func(t *CookieTransport) { t.partitioned = partitioned }
}

// CookieTransportPersistent sets whether the cookie outlives the browser. The
// default is true: the cookie's Expires and Max-Age attributes match the
// session's expiry. With false the cookie has neither, and the browser drops it
// when it closes; the session still expires on the server as usual.
func CookieTransportPersistent(persistent bool) CookieTransportOption {
	return func(t *CookieTransport) { t.persistent = persistent }
}

// CookieTransportMaxCredentialSize sets the largest credential, in bytes, that
// the transport reads or writes. The default is 4096. Browsers limit the size
// of a cookie, so stateless stores such as CookieStore must stay well below
// that limit.
func CookieTransportMaxCredentialSize(n int) CookieTransportOption {
	return func(t *CookieTransport) { t.maxCredentialSize = n }
}

// NewCookieTransport returns a CookieTransport for the cookie called name.
//
// It returns an errors.ErrInvalidArgument error if the configuration is
// invalid: an invalid cookie name, path, or domain, a non-positive maximum
// credential size, or
// Partitioned or SameSite=None without Secure. Browsers would otherwise reject
// such cookies silently.
func NewCookieTransport(name string, opts ...CookieTransportOption) (*CookieTransport, error) {
	t := &CookieTransport{
		name:              name,
		path:              "/",
		secure:            true,
		httpOnly:          true,
		sameSite:          http.SameSiteLaxMode,
		persistent:        true,
		maxCredentialSize: cookieDefaultMaxCredentialSize,
		now:               time.Now,
	}

	for _, opt := range opts {
		opt(t)
	}

	if err := t.validate(); err != nil {
		return nil, errors.ErrInvalidArgument.Wrap(err, "cookie transport")
	}

	return t, nil
}

func (t *CookieTransport) validate() error {
	switch {
	case t.name == "":
		return fmt.Errorf("cookie name is required")
	case t.maxCredentialSize <= 0:
		return fmt.Errorf("max credential size must be positive, got %d", t.maxCredentialSize)
	case t.sameSite == http.SameSiteNoneMode && !t.secure:
		return fmt.Errorf("SameSite=None requires Secure")
	}

	return t.cookie("x").Valid()
}

// Read returns the value of the configured cookie.
//
// A request without the cookie returns ErrNoCredential. More than one cookie
// with the configured name (for example, one left behind with a different
// path) is ambiguous and returns ErrInvalidSession, as does an empty or
// oversized value. The standard library drops cookies whose values are not
// syntactically valid, so those read as absent.
func (t *CookieTransport) Read(r *http.Request) (string, error) {
	cookies := r.CookiesNamed(t.name)

	switch {
	case len(cookies) == 0:
		return "", ErrNoCredential.Msg("cookie transport: no session cookie")
	case len(cookies) > 1:
		return "", ErrInvalidSession.Msgf("cookie transport: %d session cookies presented", len(cookies))
	}

	value := cookies[0].Value

	switch {
	case value == "":
		return "", ErrInvalidSession.Msg("cookie transport: empty session cookie")
	case len(value) > t.maxCredentialSize:
		return "", ErrInvalidSession.Msgf("cookie transport: session cookie of %d bytes exceeds the %d byte limit", len(value), t.maxCredentialSize)
	}

	return value, nil
}

// Write adds a Set-Cookie header that issues credential. A persistent cookie
// expires at params.ExpiresAt. A credential that is
// empty, too large, or contains anything but RFC 6265 cookie-octets is refused
// with an operational error, because net/http would otherwise quote or strip
// it silently.
func (t *CookieTransport) Write(w http.ResponseWriter, _ *http.Request, credential string, params TransportParams) error {
	switch {
	case credential == "":
		return errors.ErrInternal.Msg("cookie transport: empty credential")
	case len(credential) > t.maxCredentialSize:
		return errors.ErrInternal.Msgf("cookie transport: credential of %d bytes exceeds the %d byte limit", len(credential), t.maxCredentialSize)
	case !isCookieOctets(credential):
		return errors.ErrInternal.Msg("cookie transport: credential contains characters not allowed in a cookie value")
	}

	c := t.cookie(credential)
	if err := c.Valid(); err != nil {
		return errors.ErrInternal.Wrap(err, "cookie transport: invalid credential")
	}

	if t.persistent {
		// Max-Age is whole seconds: round up, and never send Max-Age=0,
		// which would delete the cookie.
		maxAge := (params.ExpiresAt.Sub(t.now()) + time.Second - 1) / time.Second
		c.MaxAge = int(max(maxAge, 1))
		c.Expires = params.ExpiresAt.UTC()
	}

	http.SetCookie(w, c)

	return nil
}

// Clear adds a Set-Cookie header that expires the cookie. It uses the same
// name, path, and domain as Write, because browsers only replace a cookie with
// the same identity.
func (t *CookieTransport) Clear(w http.ResponseWriter, _ *http.Request) error {
	c := t.cookie("")
	c.MaxAge = -1
	c.Expires = time.Unix(1, 0).UTC()

	http.SetCookie(w, c)

	return nil
}

func (t *CookieTransport) cookie(value string) *http.Cookie {
	c := &http.Cookie{
		Name:        t.name,
		Value:       value,
		Path:        t.path,
		Domain:      t.domain,
		Secure:      t.secure,
		HttpOnly:    t.httpOnly,
		SameSite:    t.sameSite,
		Partitioned: t.partitioned,
	}

	return c
}

// isCookieOctets reports whether s contains only RFC 6265 cookie-octets:
// visible ASCII except space, double quote, comma, semicolon, and backslash.
func isCookieOctets(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x20 || c >= 0x7f || c == '"' || c == ',' || c == ';' || c == '\\' {
			return false
		}
	}

	return true
}
