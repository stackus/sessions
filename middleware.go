package sessions

import (
	"net/http"
)

// SaveSessions returns an http.Handler that calls sessions.Save(w, r) after
// next returns. Save errors are discarded; call sessions.Save(w, r) explicitly
// if you need to handle them.
func SaveSessions(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rb := &responseBuffer{ResponseWriter: w}
		next.ServeHTTP(rb, r)
		_ = Save(w, r)
		rb.flush()
	})
}

type responseBuffer struct {
	http.ResponseWriter
	status  int
	body    []byte
	written bool
}

func (rb *responseBuffer) WriteHeader(status int) {
	if !rb.written {
		rb.status = status
		rb.written = true
	}
}

func (rb *responseBuffer) Write(b []byte) (int, error) {
	if !rb.written {
		rb.status = http.StatusOK
		rb.written = true
	}
	rb.body = append(rb.body, b...)
	return len(b), nil
}

func (rb *responseBuffer) flush() {
	if rb.written {
		rb.ResponseWriter.WriteHeader(rb.status)
	}
	if len(rb.body) > 0 {
		_, _ = rb.ResponseWriter.Write(rb.body)
	}
}
