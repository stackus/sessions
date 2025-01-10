package sessions

import (
	"net/http"
)

type Session[T any] struct {
	Values   T
	IsNew    bool
	storeKey string
	options  CookieOptions
	manager  SessionManager[T]
}

// Expire will set the MaxAge of the session to -1, effectively deleting the
// session next time it is saved.
func (s *Session[T]) Expire() {
	s.options.MaxAge = -1
}

// DoNotPersist will set the MaxAge of the session to 0, signaling to the
// store that the session should not be persisted.
//
// This is useful for situations where you have implemented a "Remember Me"
// feature and have defaulted the manager to persist sessions.
func (s *Session[T]) DoNotPersist() {
	s.options.MaxAge = 0
}

// Persist will set the MaxAge of the session to maxAge value, signaling to the
// store that the session should be persisted.
//
// This is useful for situations where you have implemented a "Remember Me"
// feature and have defaulted the manager to not persist sessions.
func (s *Session[T]) Persist(maxAge int) {
	s.options.MaxAge = maxAge
}

// Save will initiate the saving of the session to the store and the response.
func (s *Session[T]) Save(w http.ResponseWriter, r *http.Request) error {
	return s.manager.Save(w, r, s)
}

// Delete will delete the session from the store and the response.
//
// This is a convenience method that sets the MaxAge of the session to -1 and saves the session.
func (s *Session[T]) Delete(w http.ResponseWriter, r *http.Request) error {
	s.options.MaxAge = -1
	return s.manager.Save(w, r, s)
}
