package sessions

import (
	"context"
	"time"
)

// StoreParams carries the manager's settings for one store call. It is a
// struct so that fields can be added without changing the Store interface.
type StoreParams struct {
	// ExpiresAt is the absolute expiry of the record being written. It is zero
	// on Load, before the record has been decoded. A store may use it to expire
	// or clean up records, or to exclude expired ones from lookups; the manager
	// enforces expiry from the authenticated record either way.
	ExpiresAt time.Time
	// MaxRecordSize is the largest record, in bytes, the manager writes or
	// accepts. The manager checks it on every write; a store uses it to bound
	// what it reads.
	MaxRecordSize int
	// SubjectID is the application identity associated with the record, as
	// reported by a values type that implements SubjectIdentifier. It is empty
	// for unassociated sessions and on Load, before decoding. A server-side
	// store may index it to find records for revocation.
	SubjectID string
}

// SubjectIdentifier is implemented by a session values type that associates
// sessions with an application identity. The manager calls SubjectID on the
// values being written and passes the result to every Store Create and Update
// in StoreParams. An empty ID means the session is unassociated. Implement it
// with a value receiver so the manager's values type satisfies it.
type SubjectIdentifier interface {
	SubjectID() string
}

// Store persists encoded session records and locates them by credential.
//
// A Store receives each record as opaque bytes that have already been
// serialized and encoded by the manager. It never parses session values,
// cryptography, timestamps, or HTTP.
//
// Contracts:
//   - Create stores a new record and returns a new credential for it.
//   - Every Create and Update receives the record's expiry in StoreParams, and
//     its subject ID when the values type implements SubjectIdentifier. Update receives a later expiry when the
//     session was extended.
//   - Update replaces an existing record and returns its current credential,
//     or a replacement credential if the store changes it on every write. It
//     must not create a missing record.
//   - Load returns the record for a credential, or an error matching
//     ErrSessionNotFound when there is no such record.
//   - Delete removes a record and is idempotent: deleting a record that does
//     not exist succeeds.
//   - A credential the store cannot interpret makes Load and Update return an
//     error matching ErrInvalidSession, and makes Delete return
//     ErrInvalidSession, ErrSessionNotFound, or nil. In no case is any record
//     touched.
//   - ctx derives from the request: for Create and Update, the request as it
//     entered Manager.Middleware; for Load and Delete, the request passed to
//     the Manager method. A store may read request-scoped values from it, such
//     as client details placed by middleware that wraps Manager.Middleware.
//   - Operational failures (I/O, unavailable backends) are returned with a
//     built-in category such as errors.ErrInternal or errors.ErrUnavailable,
//     never with ErrInvalidSession or ErrSessionNotFound, so that they are not
//     mistaken for a missing or rejected session.
//
// Security: a store that hands the record itself to the client, as CookieStore
// does, must be paired with an encoder that authenticates it, such as
// HMACEncoder or AESGCMEncoder. The manager does not enforce this.
type Store interface {
	Load(ctx context.Context, credential string, params StoreParams) ([]byte, error)
	Create(ctx context.Context, data []byte, params StoreParams) (credential string, err error)
	Update(ctx context.Context, credential string, data []byte, params StoreParams) (newCredential string, err error)
	Delete(ctx context.Context, credential string) error
}
