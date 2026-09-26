package sessions

import (
	"net/http"
)

// scope is the per-request, per-manager session state installed by
// Manager.Middleware. It is never exposed to applications.
type scope[T any] struct {
	manager *Manager[T]
	request *http.Request // the derived request that carries this scope

	// active is the session Load and New return for this request.
	active *Session[T]
	// replaced is the persisted session superseded by New, whose record is
	// deleted when the replacement is saved.
	replaced *Session[T]

	// loadErr caches an expected rejection from the single credential lookup.
	// Operational failures are never cached, so a later Load retries.
	loadErr error
	// presented is the credential the request carried, once read.
	presented string
	// pendingCleanup records that the presented credential was rejected and
	// should be cleared from the client.
	pendingCleanup bool
	// issued holds the credentials issued to the client during this request.
	issued []string
	// deleted records that the session was deleted in this request.
	deleted bool
}

// replaceActive makes sess the active session. A superseded persisted session
// becomes the one whose record the replacement deletes when saved. A
// superseded session that was never persisted is simply retired; the record
// awaiting deletion, if any, stays the one the request started with.
func (s *scope[T]) replaceActive(sess *Session[T]) {
	if old := s.active; old != nil {
		switch old.state {
		case statePersisted:
			old.state = stateReplaced
			s.replaced = old
		case stateNew:
			old.state = stateReplaced
		}
	}

	s.active = sess
}
