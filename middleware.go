package sessions

import (
	"net/http"
)

// SaveMiddleware returns an http.Handler that calls sessions.Save(w, r) after
// next returns. Save errors are discarded; call sessions.Save(w, r) explicitly
// if you need to handle them.
func SaveMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		_ = Save(w, r)
	})
}
