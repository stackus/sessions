package sessions

import (
	"net/http"

	"github.com/stackus/errors"
)

// Load returns the request's existing session. It never creates one.
//
// It returns the session already active in this request, whether loaded
// earlier or created with New. Otherwise it reads the presented credential,
// loads and decodes the record, and checks its expiry, once per request.
// Repeated calls return the same session, so unsaved changes are never
// overwritten by a reload.
//
// When there is no usable session, Load returns nil and one of the
// unavailable errors (see IsNoSession; LoadOrNew creates a session instead):
//   - ErrNoSession: the request carries no credential;
//   - ErrInvalidSession: the credential or its record is malformed, fails
//     authentication, or is too large;
//   - ErrSessionNotFound: the record no longer exists;
//   - ErrSessionExpired: the session's lifetime has passed;
//   - ErrSessionDeleted: the session was deleted earlier in this request.
//
// These outcomes are remembered for the rest of the request. Load does not
// clear a rejected credential from the client; call Manager.Delete, or save a
// new session, to replace it. It also never creates a replacement session;
// call New when the application wants one.
//
// Any other error is an operational failure (store, encoder, transport, or
// deserialization), returned as the component reported it. It is not
// remembered, so a later Load retries. Load returns ErrNoScope if Middleware is
// not installed.
func (m *Manager[T]) Load(r *http.Request) (*Session[T], error) {
	s, err := m.scopeFrom(r)
	if err != nil {
		return nil, err
	}
	if s.active != nil {
		return s.active, nil
	}
	if s.loadErr != nil {
		return nil, s.loadErr
	}

	sess, err := m.load(r, s)

	if err != nil {
		if IsNoSession(err) {
			s.loadErr = err
			s.pendingCleanup = !errors.Is(err, ErrNoSession)
		}
		return nil, err
	}

	s.active = sess

	return sess, nil
}

// LoadOrNew returns the request's existing session or, when there is none (any
// outcome for which IsNoSession reports true), a new one created with New. Use
// Session.IsNew to tell them apart.
//
// Like New, it persists nothing: a new session is saved only if it is changed.
// A rejected credential is replaced when the new session is saved, and is
// otherwise left for Manager.Delete to clear. After Delete in the same request
// it returns a fresh session.
//
// Any error is an operational failure, or ErrNoScope if Middleware is not
// installed.
func (m *Manager[T]) LoadOrNew(r *http.Request) (*Session[T], error) {
	sess, err := m.Load(r)
	if IsNoSession(err) {
		return m.New(r)
	}

	return sess, err
}

// load performs the credential lookup. Expected rejections are returned as the
// unavailable kinds; everything else is returned unchanged.
func (m *Manager[T]) load(r *http.Request, s *scope[T]) (*Session[T], error) {
	credential, err := m.transport.Read(r)

	switch {
	case errors.Is(err, ErrNoCredential):
		return nil, ErrNoSession.Wrap(err, "load session")
	case err != nil:
		return nil, err // ErrInvalidSession, or operational
	}

	s.presented = credential

	record, err := m.store.Load(r.Context(), credential, StoreParams{MaxRecordSize: m.settings.maxRecordSize})
	if err != nil {
		return nil, err // ErrInvalidSession, ErrSessionNotFound, or operational
	}

	if len(record) > m.settings.maxRecordSize {
		return nil, ErrInvalidSession.Msgf("load session: record of %d bytes exceeds the %d byte limit", len(record), m.settings.maxRecordSize)
	}

	payload, refresh, err := decodeWithRefresh(m.encoder, record)

	switch {
	case errors.Is(err, ErrInvalidEncoding):
		return nil, ErrInvalidSession.Wrap(err, "load session")
	case err != nil:
		return nil, err
	}

	values, meta, err := unmarshalEnvelope[T](payload, m.now(), m.settings.maxPayloadSize)
	if err != nil {
		return nil, err // ErrInvalidSession, ErrSessionExpired, or operational
	}

	return &Session[T]{
		values:       values,
		state:        statePersisted,
		needsRefresh: refresh,
		credential:   credential,
		meta:         meta,
		scope:        s,
	}, nil
}
