package sessions

import (
	"net/http"

	"github.com/stackus/errors"
)

// RequireSession returns middleware that calls next only when the request has
// a session, and onFailure when it has none (any IsNoSession outcome from
// Manager.Load).
//
// It checks whether a session exists; it does not decide what the session
// grants. It must run inside m.Middleware(). A session created with
// Manager.New earlier in the same request counts as present, because Load
// returns it.
//
// An operational failure, including a missing Middleware, is never treated as
// "no session": the helper responds with the error's HTTP status and public
// message and calls neither handler. onFailure can call m.Load to see why the
// session is unavailable. A rejected credential is not cleared automatically;
// onFailure may call m.Delete to clear it.
func RequireSession[T any](m *Manager[T], onFailure http.Handler) func(http.Handler) http.Handler {
	return RequireSessionState(m, func(*Session[T]) bool { return true }, onFailure)
}

// RequireSessionState returns middleware that calls next only when the request
// has a session and check reports true for it. It calls onFailure when there
// is no session or check reports false. check is not called without a
// session.
//
// Otherwise it behaves like RequireSession.
func RequireSessionState[T any](m *Manager[T], check func(*Session[T]) bool, onFailure http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := loadForHelper(m, w, r)

			switch {
			case !ok:
			case sess != nil && check(sess):
				next.ServeHTTP(w, r)
			default:
				onFailure.ServeHTTP(w, r)
			}
		})
	}
}

// GuestOnly returns middleware that calls next only when the request has no
// session, and onFailure when it has one. Use it for routes such as login or
// registration, to redirect visitors who already have a session.
//
// Otherwise it behaves like RequireSession.
func GuestOnly[T any](m *Manager[T], onFailure http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := loadForHelper(m, w, r)

			switch {
			case !ok:
			case sess != nil:
				onFailure.ServeHTTP(w, r)
			default:
				next.ServeHTTP(w, r)
			}
		})
	}
}

// loadForHelper loads the request's session. It returns the session, or nil
// when the session is unavailable. On an operational failure it writes the
// error response and returns ok false.
func loadForHelper[T any](m *Manager[T], w http.ResponseWriter, r *http.Request) (sess *Session[T], ok bool) {
	sess, err := m.Load(r)

	switch {
	case err == nil:
		return sess, true
	case IsNoSession(err):
		return nil, true
	}

	http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))

	return nil, false
}
