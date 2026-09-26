// Package sessions manages HTTP session data for Go servers.
//
// The package stores, loads, and deletes session values of an application
// defined type T. It does not implement authentication or authorization: the
// application decides what session values mean and when to create, change, or
// delete a session.
//
// # Components
//
// A Manager is built from three independent components, each with its own
// constructor and requirements:
//
//   - A Transport carries the credential over HTTP: CookieTransport for
//     browsers, BearerTransport for CLI and API clients.
//   - An Encoder transforms the serialized session record: Base64Encoder
//     (representation only), HMACEncoder (authenticated, but readable), and
//     AESGCMEncoder (authenticated and encrypted). RotatingEncoder adds key
//     rotation.
//   - A Store persists records: CookieStore keeps the whole record in the
//     client's credential, FileStore keeps it on the server under a random ID.
//
// NewManager does not judge whether a combination is secure. A store that
// hands the record to the client, such as CookieStore, must be paired with an
// authenticating encoder; CookieStore with Base64Encoder lets clients read and
// forge their sessions.
//
// # Lifecycle
//
// Every route that uses sessions must be wrapped with Manager.Middleware,
// which installs a per-request scope and does no other work. A request that
// never touches the session API performs no session work at all.
//
// Sessions are never created implicitly. Manager.Load returns the request's
// existing session, or an error for which IsNoSession reports true when
// there is none (no credential, or one that is invalid, expired, or refers to
// a missing record). Manager.New creates a session in memory only, and
// Manager.LoadOrNew returns the existing session or a new one, so its errors
// are always operational failures. Values are
// changed with Session.Set and Session.Update, and Session.Save commits them
// once, before the response is written: it persists only what changed and
// issues a credential only when it is new or changed. Manager.Delete and
// Session.Delete delete the session and clear its credential, even when the
// credential cannot be decoded.
//
// A session expires a fixed lifetime (WithLifetime) after it was first saved.
// Session.ExpiresAt reports when, and Session.Extend restarts the lifetime.
// The manager passes each record's expiry and the record size limit to the
// store and transport, so neither is configured twice.
//
// # Errors
//
// Errors are github.com/stackus/errors kinds. IsNoSession separates the
// expected "no usable session" outcomes from operational failures such as an
// unreachable store, which are never hidden. Every error carries an HTTP
// status and a message that is safe to show to clients:
//
//	http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
//
// Constructors that validate configuration return an error rather than
// panicking.
package sessions
