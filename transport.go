package sessions

import (
	"net/http"
	"time"
)

// TransportParams carries the manager's settings for one credential write. It
// is a struct so that fields can be added without changing the Transport
// interface.
type TransportParams struct {
	// ExpiresAt is the absolute expiry of the session the credential refers
	// to. A transport may use it to tell the client how long to keep the
	// credential.
	ExpiresAt time.Time
}

// Transport carries session credentials between the client and the server
// over HTTP. It deals only with opaque credential strings; it knows nothing
// about record formats or session values.
//
// Contracts:
//   - Read returns an error matching ErrNoCredential only when the request
//     carries no credential.
//   - Read returns an error matching ErrInvalidSession for a malformed or
//     ambiguous credential. Error messages never include the credential.
//   - Any other error from Read is treated as an operational failure.
//   - Write issues a credential to the client and Clear asks the client to
//     discard it. Write is also called with an unchanged credential when the
//     session is extended, so the client learns the new expiry. Both only work before the response is committed, that is,
//     before the first WriteHeader, Write, or Flush. The transport cannot
//     always detect a committed response, particularly through third-party
//     ResponseWriter wrappers.
//
// Write and Clear express what the server intends. The library cannot
// guarantee that the client receives or obeys them.
type Transport interface {
	Read(r *http.Request) (credential string, err error)
	Write(w http.ResponseWriter, r *http.Request, credential string, params TransportParams) error
	Clear(w http.ResponseWriter, r *http.Request) error
}
