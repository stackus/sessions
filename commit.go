package sessions

import (
	"context"
	"net/http"
	"time"

	"github.com/stackus/errors"
)

// Save commits the session: it persists the session if it needs to be and
// issues its credential to the client if the credential is new or changed.
// Call it before the response is committed, that is, before the first
// WriteHeader, Write, or Flush; the library cannot always detect a committed
// response.
//
// Save commits at most once. Afterwards Set and Update return
// ErrSessionCommitted and further calls to Save do nothing and return nil. A
// session that was never changed is not persisted, but is still committed.
//
// If Save fails, the session is not committed and keeps its changes, so the
// caller can report the error or try again. Saving to the store and issuing
// the credential are not one transaction: if issuing the new credential fails
// after the record was created, Save deletes that record on a best-effort
// basis, and a record that cannot be deleted remains until it expires.
//
// Saving a session created with New issues a new credential, which replaces
// the one the client presented. When New replaced a session loaded in the same
// request, Save then deletes the old record; if that deletion fails, Save
// returns the error but the new session is already committed. Without a prior
// Load the old record is not deleted and remains until it expires. With a
// stateless store such as CookieStore, copies of an old credential stay valid
// until they expire.
//
// Save returns ErrSessionDeleted for a deleted session and ErrSessionReplaced
// for a session replaced by Manager.New.
func (s *Session[T]) Save(w http.ResponseWriter) error {
	switch {
	case s.state == stateDeleted:
		return ErrSessionDeleted
	case s.state == stateReplaced:
		return ErrSessionReplaced
	case s.committed:
		return nil
	}
	return s.scope.commit(w, s)
}

// commit makes every persistence decision for sess. It is the single commit
// path for the request.
func (sc *scope[T]) commit(w http.ResponseWriter, sess *Session[T]) error {
	switch {
	case sess.state == stateNew && sess.dirty:
		return sc.create(w, sess)
	case sess.state == statePersisted && (sess.dirty || sess.needsRefresh || sess.unsent || sess.extended):
		return sc.update(w, sess)
	}
	sess.committed = true // untouched new session or unchanged loaded session
	return nil
}

// create persists a new session, issues its credential, and then deletes the
// record of the session it replaced, if any.
func (sc *scope[T]) create(w http.ResponseWriter, sess *Session[T]) error {
	m := sc.manager
	ctx := sc.request.Context()

	now := time.Unix(m.now().Unix(), 0) // envelopes store whole seconds
	meta := envelopeMeta{CreatedAt: now, ExpiresAt: now.Add(m.settings.lifetime)}
	record, err := m.encodeRecord(sess.values, meta)
	if err != nil {
		return err
	}

	credential, err := m.store.Create(ctx, record, m.storeParams(sess.values, meta))
	if err != nil {
		return errors.Wrap(err, "session save: create record")
	}

	if err := m.transport.Write(w, sc.request, credential, TransportParams{ExpiresAt: meta.ExpiresAt}); err != nil {
		// The client never received this credential; do not leave an orphan.
		_ = m.deleteRecord(ctx, credential)
		return errors.Wrap(err, "session save: issue credential")
	}

	sess.state = statePersisted
	sess.credential = credential
	sess.meta = meta
	sess.dirty = false
	sess.committed = true
	sc.issued = append(sc.issued, credential)
	sc.pendingCleanup = false

	if old := sc.replaced; old != nil {
		sc.replaced = nil
		if err := m.deleteRecord(ctx, old.credential); err != nil {
			return errors.Wrap(err, "session save: delete replaced record")
		}
	}

	return nil
}

// update rewrites an existing record, keeping its expiry unless the session was
// extended, and issues the credential if the store changed it or the session
// was extended.
func (sc *scope[T]) update(w http.ResponseWriter, sess *Session[T]) error {
	m := sc.manager
	record, err := m.encodeRecord(sess.values, sess.meta)
	if err != nil {
		return err
	}

	credential, err := m.store.Update(sc.request.Context(), sess.credential, record, m.storeParams(sess.values, sess.meta))
	if err != nil {
		return errors.Wrap(err, "session save: update record")
	}

	if credential != sess.credential {
		sess.credential = credential
		sess.unsent = true
	}

	if sess.unsent || sess.extended {
		if err := m.transport.Write(w, sc.request, credential, TransportParams{ExpiresAt: sess.meta.ExpiresAt}); err != nil {
			return errors.Wrap(err, "session save: issue credential")
		}
		sess.unsent = false
		sc.issued = append(sc.issued, credential)
	}

	sess.dirty = false
	sess.needsRefresh = false
	sess.extended = false
	sess.committed = true

	return nil
}

// storeParams returns the store parameters for writing values with meta.
func (m *Manager[T]) storeParams(values T, meta envelopeMeta) StoreParams {
	params := StoreParams{ExpiresAt: meta.ExpiresAt, MaxRecordSize: m.settings.maxRecordSize}
	if s, ok := any(values).(SubjectIdentifier); ok {
		params.SubjectID = s.SubjectID()
	}
	return params
}

// encodeRecord serializes and encodes values into a store record. Every
// failure is operational.
func (m *Manager[T]) encodeRecord(values T, meta envelopeMeta) ([]byte, error) {
	payload, err := marshalEnvelope(values, meta, m.settings.maxPayloadSize)
	if err != nil {
		return nil, errors.Wrap(err, "session save")
	}

	record, err := m.encoder.Encode(payload)
	if err != nil {
		return nil, errors.Wrap(err, "session save: encode record")
	}

	if len(record) > m.settings.maxRecordSize {
		return nil, errors.ErrInternal.Msgf("session save: record of %d bytes exceeds the %d byte limit", len(record), m.settings.maxRecordSize)
	}

	return record, nil
}

// deleteRecord deletes the record for credential. A credential the store
// cannot interpret, or whose record is already gone, has nothing to delete.
func (m *Manager[T]) deleteRecord(ctx context.Context, credential string) error {
	err := m.store.Delete(ctx, credential)
	if errors.Is(err, ErrInvalidSession) || errors.Is(err, ErrSessionNotFound) {
		return nil
	}

	return err
}
