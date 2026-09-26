package sessions

import (
	"net/http"
	"strings"

	"github.com/stackus/errors"
)

const (
	bearerDefaultTokenHeader       = "Session-Token"
	bearerDefaultMaxCredentialSize = 4096
)

// BearerTransport reads the session credential from an
// "Authorization: Bearer <credential>" request header and issues it in an
// application-defined response header, Session-Token by default. It suits CLI
// and API clients that store the token themselves and replay it.
//
// The response headers form a protocol between the application and its
// clients:
//   - Write sets "<header>: <credential>" when a session is created or its
//     credential changes. With a server-side store the credential is stable,
//     so it is not re-sent on every request.
//   - Clear sets "<header>-Action: clear". This asks the client to discard its
//     token; it cannot remove a token the client has stored. The client must
//     implement that step.
//
// Both set "Cache-Control: no-store". Within one response the last of Write
// and Clear wins; the other's header is removed.
//
// Browser JavaScript clients can only read these headers when they are listed
// in Access-Control-Expose-Headers; ordinary CLI clients are unaffected.
// Credentials are secrets: keep them out of logs, traces, and URLs, and use
// TLS outside local development.
//
// A stateless credential (from CookieStore) changes on every update, and a
// client that misses a response carrying the new one keeps a stale token.
// Prefer a server-side store such as FileStore for CLI clients.
type BearerTransport struct {
	tokenHeader       string
	actionHeader      string
	maxCredentialSize int
}

var _ Transport = (*BearerTransport)(nil)

// BearerTransportOption configures a BearerTransport.
type BearerTransportOption func(*BearerTransport)

// BearerTransportTokenHeader sets the response header that carries issued
// credentials. The clear signal uses the same name with an "-Action" suffix.
// The default is "Session-Token". Authorization is not allowed.
func BearerTransportTokenHeader(name string) BearerTransportOption {
	return func(t *BearerTransport) { t.tokenHeader = name }
}

// BearerTransportMaxCredentialSize sets the largest credential, in bytes, that
// the transport reads or writes. The default is 4096.
func BearerTransportMaxCredentialSize(n int) BearerTransportOption {
	return func(t *BearerTransport) { t.maxCredentialSize = n }
}

// NewBearerTransport returns a BearerTransport. It returns an
// errors.ErrInvalidArgument error if the token header is not a valid header
// name or is Authorization, or if the maximum credential size is not positive.
func NewBearerTransport(opts ...BearerTransportOption) (*BearerTransport, error) {
	t := &BearerTransport{
		tokenHeader:       bearerDefaultTokenHeader,
		maxCredentialSize: bearerDefaultMaxCredentialSize,
	}

	for _, opt := range opts {
		opt(t)
	}

	switch {
	case !isHTTPToken(t.tokenHeader):
		return nil, errors.ErrInvalidArgument.Msgf("bearer transport: invalid token header name %q", t.tokenHeader)
	case strings.EqualFold(t.tokenHeader, "Authorization"):
		return nil, errors.ErrInvalidArgument.Msg("bearer transport: Authorization must not be used as the response token header")
	case t.maxCredentialSize <= 0:
		return nil, errors.ErrInvalidArgument.Msgf("bearer transport: max credential size must be positive, got %d", t.maxCredentialSize)
	}

	t.tokenHeader = http.CanonicalHeaderKey(t.tokenHeader)
	t.actionHeader = http.CanonicalHeaderKey(t.tokenHeader + "-Action")

	return t, nil
}

// Read returns the bearer credential from the Authorization header.
//
// A request without an Authorization header, or with a scheme other than
// Bearer (which may belong to another authentication mechanism), returns
// ErrNoCredential. More than one Authorization header, a missing or malformed
// token, or a token over the size limit returns ErrInvalidSession.
func (t *BearerTransport) Read(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")

	switch {
	case len(values) == 0:
		return "", ErrNoCredential.Msg("bearer transport: no authorization header")
	case len(values) > 1:
		return "", ErrInvalidSession.Msgf("bearer transport: %d authorization headers presented", len(values))
	}

	scheme, rest, _ := strings.Cut(values[0], " ")

	if !strings.EqualFold(scheme, "Bearer") {
		return "", ErrNoCredential.Msg("bearer transport: authorization scheme is not Bearer")
	}

	token := strings.TrimLeft(rest, " ")

	switch {
	case token == "":
		return "", ErrInvalidSession.Msg("bearer transport: missing bearer token")
	case len(token) > t.maxCredentialSize:
		return "", ErrInvalidSession.Msgf("bearer transport: bearer token of %d bytes exceeds the %d byte limit", len(token), t.maxCredentialSize)
	case !isToken68(token):
		return "", ErrInvalidSession.Msg("bearer transport: malformed bearer token")
	}

	return token, nil
}

// Write sets the token header to credential and removes any clear signal set
// earlier in this response. A credential that is empty, too large, or not a
// valid bearer token is refused with an operational error.
func (t *BearerTransport) Write(w http.ResponseWriter, _ *http.Request, credential string, _ TransportParams) error {
	switch {
	case credential == "":
		return errors.ErrInternal.Msg("bearer transport: empty credential")
	case len(credential) > t.maxCredentialSize:
		return errors.ErrInternal.Msgf("bearer transport: credential of %d bytes exceeds the %d byte limit", len(credential), t.maxCredentialSize)
	case !isToken68(credential):
		return errors.ErrInternal.Msg("bearer transport: credential is not a valid bearer token")
	}

	h := w.Header()
	h.Del(t.actionHeader)
	h.Set(t.tokenHeader, credential)
	h.Set("Cache-Control", "no-store")

	return nil
}

// Clear sets "<header>-Action: clear" and removes any credential set earlier
// in this response.
func (t *BearerTransport) Clear(w http.ResponseWriter, _ *http.Request) error {
	h := w.Header()
	h.Del(t.tokenHeader)
	h.Set(t.actionHeader, "clear")
	h.Set("Cache-Control", "no-store")

	return nil
}

// isToken68 reports whether s matches the RFC 9110 token68 syntax:
// 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=".
func isToken68(s string) bool {
	body := strings.TrimRight(s, "=")
	if body == "" {
		return false
	}

	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~', c == '+', c == '/':
		default:
			return false
		}
	}

	return true
}

// isHTTPToken reports whether s is a non-empty RFC 9110 token, the syntax of a
// header field name.
func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}

	return true
}
