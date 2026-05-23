package sessions

import "net/http"

// RequireSession returns middleware that calls onFailure if no valid session exists.
// A session is valid when IsNew is false (cookie was decoded successfully).
// manager.Get errors are treated as no session.
func RequireSession[T any](mgr SessionManager[T], onFailure http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := mgr.Get(r)
			if err != nil || session.IsNew {
				onFailure.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSessionState returns middleware that calls onFailure if no valid session exists
// or if check returns false. The check is never called for new sessions or on Get errors.
func RequireSessionState[T any](mgr SessionManager[T], check func(*Session[T]) bool, onFailure http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := mgr.Get(r)
			if err != nil || session.IsNew || !check(session) {
				onFailure.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GuestOnly returns middleware that calls onFailure if a valid session exists.
// Use for login or registration routes to redirect already-authenticated users.
func GuestOnly[T any](mgr SessionManager[T], onFailure http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := mgr.Get(r)
			if err == nil && !session.IsNew {
				onFailure.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
