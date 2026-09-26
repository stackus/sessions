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
}

// Store persists encoded session records and locates them by credential.
//
// A Store receives each record as opaque bytes that have already been
// serialized and encoded by the manager. It never parses session values,
// cryptography, timestamps, or HTTP.
//
// Contracts:
//   - Create stores a new record and returns a new credential for it.
//   - Every Create and Update receives the record's expiry in StoreParams.
//     Update receives a later expiry when the session was extended.
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
