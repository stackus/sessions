package sessions

import (
	"github.com/stackus/errors"
)

// Expected absent or rejected outcomes. IsNoSession reports true for these.
// Each is classified as errors.ErrUnauthenticated (HTTP 401) and carries a
// public message that is safe to show to clients.
var (
	// ErrNoSession is returned by Manager.Load when the request presents no
	// session credential.
	ErrNoSession = errors.NewKind("SESSION_NONE", errors.ErrUnauthenticated,
		"no session credential presented",
		errors.WithPublicMessage("A session is required"))

	// ErrInvalidSession is returned by Manager.Load when the presented
	// credential or its record is malformed, ambiguous, or fails
	// authentication. The specific cause is wrapped.
	ErrInvalidSession = errors.NewKind("SESSION_INVALID", errors.ErrUnauthenticated,
		"session credential rejected",
		errors.WithPublicMessage("The session is invalid"))

	// ErrSessionExpired is returned by Manager.Load when the session's
	// absolute lifetime has passed.
	ErrSessionExpired = errors.NewKind("SESSION_EXPIRED", errors.ErrUnauthenticated,
		"session expired",
		errors.WithPublicMessage("The session has expired"))

	// ErrSessionNotFound is returned by Manager.Load when the credential is
	// well-formed but the store holds no record for it. Stores return it from
	// Load for missing records.
	ErrSessionNotFound = errors.NewKind("SESSION_NOT_FOUND", errors.ErrUnauthenticated,
		"session record not found",
		errors.WithPublicMessage("The session is invalid"))

	// ErrSessionDeleted is returned by Manager.Load after the session was
	// deleted earlier in the same request, and by the methods of a deleted
	// session.
	ErrSessionDeleted = errors.NewKind("SESSION_DELETED", errors.ErrUnauthenticated,
		"session has been deleted",
		errors.WithPublicMessage("The session has ended"))
)

// Programming or configuration errors. IsNoSession reports false for these.
// Each is classified as errors.ErrInternal (HTTP 500).
var (
	// ErrNoScope is returned by every Manager method that takes a request when
	// the route is not wrapped with Manager.Middleware.
	ErrNoScope = errors.NewKind("SESSION_NO_SCOPE", errors.ErrInternal,
		"session scope is not installed; wrap the route with Manager.Middleware")

	// ErrSessionCommitted is returned when a session is modified or deleted
	// after it has been saved.
	ErrSessionCommitted = errors.NewKind("SESSION_COMMITTED", errors.ErrInternal,
		"session already committed")

	// ErrSessionReplaced is returned by the methods of a session superseded by
	// Manager.New in the same request.
	ErrSessionReplaced = errors.NewKind("SESSION_REPLACED", errors.ErrInternal,
		"session has been replaced")
)

// Component-level signals. The manager translates them into the outcomes
// above; applications normally see them only wrapped.
var (
	// ErrInvalidEncoding is returned by an Encoder's Decode for malformed or
	// unauthenticated input. The manager reports it as ErrInvalidSession.
	ErrInvalidEncoding = errors.NewKind("SESSION_INVALID_ENCODING", errors.ErrInvalidArgument,
		"invalid encoded session data")

	// ErrNoCredential is returned by a Transport's Read when the request
	// carries no credential. The manager reports it as ErrNoSession.
	ErrNoCredential = errors.NewKind("SESSION_NO_CREDENTIAL", errors.ErrUnauthenticated,
		"no transport credential")
)

var unavailable = []error{
	ErrNoSession,
	ErrInvalidSession,
	ErrSessionExpired,
	ErrSessionNotFound,
	ErrSessionDeleted,
}

// IsNoSession reports whether err means the request has no usable session
// rather than an operational failure. It covers more than the ErrNoSession
// kind: ErrNoSession, ErrInvalidSession, ErrSessionExpired,
// ErrSessionNotFound, and ErrSessionDeleted.
//
// An application may treat a request with no session as anonymous and, if it
// wants one, create a new session explicitly with Manager.New, or use
// Manager.LoadOrNew instead of Manager.Load.
func IsNoSession(err error) bool {
	for _, target := range unavailable {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
