package sessions

import (
	"net/http"
	"slices"

	"github.com/stackus/errors"
)

// Delete deletes the request's session and clears its credential from the
// client. It never loads or decodes the record, so it also clears a credential
// that Load rejected or could not read.
//
// It deletes the record of every credential known to the request: the one the
// client presented and any issued during the request. If none is known yet it
// reads the presented credential; when there is none, or it is malformed,
// there is nothing to delete, but the credential is still cleared. After a
// successful Delete, Load returns ErrSessionDeleted and every session obtained
// earlier in the request is deleted. New may then create a fresh session, for
// example an anonymous session after logout. Deleting again does nothing.
//
// Clearing is a request to the client: with a stateless store such as
// CookieStore, copies of the credential stay valid until they expire, and a
// bearer client must discard its own token.
//
// If a record cannot be deleted, Delete returns the error without clearing the
// client's credential, and nothing is marked deleted, so it can be retried.
// Delete returns ErrSessionCommitted if the request's session was already
// saved, and ErrNoScope if Middleware is not installed. Call it before the
// response is committed.
func (m *Manager[T]) Delete(w http.ResponseWriter, r *http.Request) error {
	s, err := m.scopeFrom(r)
	if err != nil {
		return err
	}

	return s.delete(w, r)
}

// Delete deletes the session. It is equivalent to Manager.Delete for the
// session's own request.
//
// It returns ErrSessionDeleted if the session was already deleted,
// ErrSessionReplaced if it was replaced by Manager.New, and
// ErrSessionCommitted if it was already saved.
func (s *Session[T]) Delete(w http.ResponseWriter) error {
	switch {
	case s.state == stateDeleted:
		return ErrSessionDeleted
	case s.state == stateReplaced:
		return ErrSessionReplaced
	case s.committed:
		return ErrSessionCommitted
	}

	return s.scope.delete(w, s.scope.request)
}

func (sc *scope[T]) delete(w http.ResponseWriter, r *http.Request) error {
	if sc.active != nil && sc.active.committed {
		return ErrSessionCommitted
	}

	credentials := sc.knownCredentials()
	if len(credentials) == 0 && sc.deleted {
		sc.markDeleted() // nothing issued since the last delete
		return nil
	}

	if len(credentials) == 0 && sc.loadErr == nil {
		credential, err := sc.manager.transport.Read(r)
		switch {
		case err == nil:
			credentials = append(credentials, credential)
		case errors.Is(err, ErrNoCredential), errors.Is(err, ErrInvalidSession):
			// Nothing to delete; the client's credential is still cleared.
		default:
			return err
		}
	}

	for _, credential := range credentials {
		if err := sc.manager.deleteRecord(r.Context(), credential); err != nil {
			return errors.Wrap(err, "session delete: delete record")
		}
	}

	if err := sc.manager.transport.Clear(w, r); err != nil {
		return errors.Wrap(err, "session delete: clear credential")
	}
	sc.markDeleted()

	return nil
}

// knownCredentials returns the distinct credentials presented or issued in
// this request.
func (sc *scope[T]) knownCredentials() []string {
	var credentials []string
	add := func(c string) {
		if c == "" {
			return
		}
		if slices.Contains(credentials, c) {
			return
		}
		credentials = append(credentials, c)
	}

	add(sc.presented)

	for _, c := range sc.issued {
		add(c)
	}

	for _, sess := range []*Session[T]{sc.active, sc.replaced} {
		if sess != nil {
			add(sess.credential)
		}
	}

	return credentials
}

// markDeleted records a completed deletion. Every session the request held is
// deleted, Load reports ErrSessionDeleted until New creates a fresh session,
// and no credential remains to delete or clean up.
func (sc *scope[T]) markDeleted() {
	for _, sess := range []*Session[T]{sc.active, sc.replaced} {
		if sess != nil {
			sess.state = stateDeleted
		}
	}

	sc.active = nil
	sc.replaced = nil
	sc.loadErr = ErrSessionDeleted
	sc.presented = ""
	sc.issued = nil
	sc.pendingCleanup = false
	sc.deleted = true
}
