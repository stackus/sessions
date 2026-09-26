package sessions

import (
	"net/http"
	"time"

	"github.com/stackus/errors"
)

type sessionState uint8

const (
	stateNew       sessionState = iota // created by Manager.New, never persisted
	statePersisted                     // loaded from, or saved to, the store
	stateDeleted                       // deleted in this request
	stateReplaced                      // superseded by Manager.New in this request
)

// Session holds the values of type T for one request, plus private lifecycle
// state. Obtain one from Manager.Load or Manager.New.
//
// A Session is request-scoped and not safe for concurrent mutation unless the
// caller synchronizes access.
type Session[T any] struct {
	values       T
	state        sessionState
	dirty        bool
	committed    bool
	needsRefresh bool // re-encode on Save, e.g. after a key rotation; not value dirtiness
	extended     bool // expiry moved by Extend; rewrite the record and reissue the credential on Save
	credential   string
	unsent       bool // credential changed but has not been delivered to the client
	meta         envelopeMeta
	scope        *scope[T]
}

// Values returns a shallow copy of the session values.
//
// The copy is read-only by convention only: maps, slices, and pointers inside
// it still refer to the session's memory. Changing them does not mark the
// session dirty, so the change may not be saved. Use Set or Update to change
// values.
func (s *Session[T]) Values() T {
	return s.values
}

// Set replaces the session values and marks the session dirty, even if the new
// values equal the old ones. Setting the zero value clears the session.
//
// It returns ErrSessionDeleted, ErrSessionReplaced, or ErrSessionCommitted if
// the session can no longer be changed.
func (s *Session[T]) Set(values T) error {
	if err := s.checkWritable(); err != nil {
		return err
	}

	s.dirty = true
	s.values = values

	return nil
}

// Update calls fn with a pointer to the session values and marks the session
// dirty. The session is marked dirty before fn runs, so it stays dirty even if
// fn panics; changes made before a panic are not rolled back.
//
// Do not keep the pointer after fn returns: later changes through it are not
// tracked and may not be saved.
//
// It returns ErrSessionDeleted, ErrSessionReplaced, or ErrSessionCommitted if
// the session can no longer be changed.
func (s *Session[T]) Update(fn func(*T)) error {
	if err := s.checkWritable(); err != nil {
		return err
	}

	s.dirty = true

	fn(&s.values)

	return nil
}

// IsDirty reports whether the values were changed with Set or Update since the
// session was loaded, created, or last saved.
func (s *Session[T]) IsDirty() bool {
	return s.dirty
}

// IsNew reports whether the session was created by Manager.New or
// Manager.LoadOrNew in this request and has not been persisted. It is false
// once Save persists the session, and for a session loaded from the store.
// Saving an untouched new session persists nothing, so it stays true.
func (s *Session[T]) IsNew() bool {
	return s.state == stateNew
}

// IsCommitted reports whether Save has succeeded for this session. Afterwards
// Set, Update, and Delete return ErrSessionCommitted. A failed Save leaves the
// session uncommitted.
func (s *Session[T]) IsCommitted() bool {
	return s.committed
}

// CreatedAt returns when the session was first saved, to the second. It is the
// zero time for a session that has not been saved yet.
func (s *Session[T]) CreatedAt() time.Time {
	return s.meta.CreatedAt
}

// ExpiresAt returns when the session expires, to the second. It is the zero
// time for a session that has not been saved yet; saving sets it to the
// manager's lifetime from then. Use time.Until(sess.ExpiresAt()) for the time
// remaining.
func (s *Session[T]) ExpiresAt() time.Time {
	return s.meta.ExpiresAt
}

// Extend restarts the session's lifetime: its expiry becomes the manager's
// lifetime from now, and Save rewrites the record and reissues the credential
// with the new expiry. The values, CreatedAt, and a server-side store's
// credential are kept, and the session is not marked dirty.
//
// Sessions otherwise expire a fixed lifetime after they were first saved.
// Calling Extend when the session nears expiry gives it a sliding expiry:
//
//	if time.Until(sess.ExpiresAt()) < lifetime/2 {
//		err = sess.Extend()
//	}
//
// Extending on every request makes every request write to the store. Compare
// CreatedAt to enforce an absolute limit on top of the sliding one.
//
// Extend does nothing for a session that has not been saved yet, because
// saving it starts its lifetime. It returns ErrSessionDeleted,
// ErrSessionReplaced, or ErrSessionCommitted if the session can no longer be
// changed.
func (s *Session[T]) Extend() error {
	if err := s.checkWritable(); err != nil {
		return err
	}

	if s.state != statePersisted {
		return nil
	}

	m := s.scope.manager
	now := time.Unix(m.now().Unix(), 0) // envelopes store whole seconds
	s.meta.ExpiresAt = now.Add(m.settings.lifetime)
	s.extended = true

	return nil
}

// checkWritable returns why the session can no longer be changed, if it can't.
// A deleted session reports ErrSessionDeleted, then a replaced one
// ErrSessionReplaced, then a committed one ErrSessionCommitted.
func (s *Session[T]) checkWritable() error {
	switch {
	case s.state == stateDeleted:
		return ErrSessionDeleted
	case s.state == stateReplaced:
		return ErrSessionReplaced
	case s.committed:
		return ErrSessionCommitted
	}

	return nil
}

// New creates a session in memory and makes it the request's active session.
// It never creates a credential, touches the store, or writes a response
// header; the session is persisted only when it is saved.
//
// New(r) creates a session with zero values that is saved only if it is then
// changed. New(r, v) creates a session with values v that is already dirty.
// Passing more than one value is an errors.ErrInvalidArgument error.
//
// If the request already has an active session, the new session replaces it,
// and the old session's methods return ErrSessionReplaced. When a loaded
// session is replaced, saving the new session deletes the old record. New
// never reads the presented credential: without a prior Load, the record the
// client's old credential refers to is not deleted and remains until it
// expires. Call Load first when the old session must be revoked, for example
// when a login raises privileges.
//
// New returns ErrNoScope if Middleware is not installed.
func (m *Manager[T]) New(r *http.Request, initial ...T) (*Session[T], error) {
	s, err := m.scopeFrom(r)
	if err != nil {
		return nil, err
	}

	if len(initial) > 1 {
		return nil, errors.ErrInvalidArgument.Msgf("sessions: New accepts at most one initial value, got %d", len(initial))
	}

	sess := &Session[T]{state: stateNew, scope: s}

	if len(initial) == 1 {
		sess.values = initial[0]
		sess.dirty = true
	}

	s.replaceActive(sess)

	return sess, nil
}
