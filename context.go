package sessions

import (
	"context"
	"net/http"
)

// sessionContextKey is a typed key combining T and cookie name.
// Prevents collisions between different session types or cookie names.
type sessionContextKey[T any] struct {
	name string
}

// StoreInContext stores a *Session[T] in the request context under a key
// derived from T and cookieName. Returns the updated *http.Request.
//
// Typical use: a middleware calls manager.Get, then StoreInContext so that
// downstream handlers can call FromContext without importing the manager.
func StoreInContext[T any](r *http.Request, cookieName string, session *Session[T]) *http.Request {
	key := sessionContextKey[T]{name: cookieName}
	return r.WithContext(context.WithValue(r.Context(), key, session))
}

// FromContext retrieves a *Session[T] stored with StoreInContext.
// Returns ErrSessionNotFound if no session is stored for the given T and cookieName.
func FromContext[T any](r *http.Request, cookieName string) (*Session[T], error) {
	key := sessionContextKey[T]{name: cookieName}
	v := r.Context().Value(key)
	if v == nil {
		return nil, ErrSessionNotFound
	}
	s, ok := v.(*Session[T])
	if !ok {
		return nil, ErrSessionNotFound
	}
	return s, nil
}
