package sessions

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type stubSessionManager[T any] struct {
	session *Session[T]
	err     error
}

func (s *stubSessionManager[T]) Get(r *http.Request) (*Session[T], error) {
	return s.session, s.err
}

func (s *stubSessionManager[T]) Save(w http.ResponseWriter, r *http.Request, session *Session[T]) error {
	return nil
}

func newSession[T any](isNew bool) *Session[T] {
	return &Session[T]{IsNew: isNew}
}

func TestRequireSession(t *testing.T) {
	type testCase struct {
		mgr      func() SessionManager[string]
		wantNext bool
	}

	tests := map[string]testCase{
		"valid_session_calls_next": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](false)}
			},
			wantNext: true,
		},
		"new_session_calls_failure": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](true)}
			},
			wantNext: false,
		},
		"get_error_calls_failure": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{err: errors.New("decode error")}
			},
			wantNext: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			var nextCalled, failureCalled bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
			onFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { failureCalled = true })
			handler := RequireSession(tc.mgr(), onFailure)(next)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			// Act
			handler.ServeHTTP(w, r)

			// Assert
			assert.Equal(t, tc.wantNext, nextCalled)
			assert.Equal(t, !tc.wantNext, failureCalled)
		})
	}
}

func TestRequireSessionState(t *testing.T) {
	type testCase struct {
		mgr        func() SessionManager[string]
		check      func(*Session[string]) bool
		wantNext   bool
		checkCalls int
	}

	tests := map[string]testCase{
		"valid_session_check_passes_calls_next": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](false)}
			},
			check:      func(*Session[string]) bool { return true },
			wantNext:   true,
			checkCalls: 1,
		},
		"valid_session_check_fails_calls_failure": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](false)}
			},
			check:      func(*Session[string]) bool { return false },
			wantNext:   false,
			checkCalls: 1,
		},
		"new_session_calls_failure_without_check": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](true)}
			},
			check: func(*Session[string]) bool {
				// should never be called for new sessions
				return true
			},
			wantNext:   false,
			checkCalls: 0,
		},
		"get_error_calls_failure_without_check": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{err: errors.New("decode error")}
			},
			check: func(*Session[string]) bool {
				// should never be called on error
				return true
			},
			wantNext:   false,
			checkCalls: 0,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			var nextCalled, failureCalled bool
			var checkCallCount int
			wrappedCheck := func(s *Session[string]) bool {
				checkCallCount++
				return tc.check(s)
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
			onFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { failureCalled = true })
			handler := RequireSessionState(tc.mgr(), wrappedCheck, onFailure)(next)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			// Act
			handler.ServeHTTP(w, r)

			// Assert
			assert.Equal(t, tc.wantNext, nextCalled)
			assert.Equal(t, !tc.wantNext, failureCalled)
			assert.Equal(t, tc.checkCalls, checkCallCount)
		})
	}
}

func TestGuestOnly(t *testing.T) {
	type testCase struct {
		mgr      func() SessionManager[string]
		wantNext bool
	}

	tests := map[string]testCase{
		"no_session_calls_next": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](true)}
			},
			wantNext: true,
		},
		"get_error_calls_next": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{err: errors.New("decode error")}
			},
			wantNext: true,
		},
		"existing_session_calls_failure": {
			mgr: func() SessionManager[string] {
				return &stubSessionManager[string]{session: newSession[string](false)}
			},
			wantNext: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			var nextCalled, failureCalled bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { nextCalled = true })
			onFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { failureCalled = true })
			handler := GuestOnly(tc.mgr(), onFailure)(next)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			// Act
			handler.ServeHTTP(w, r)

			// Assert
			assert.Equal(t, tc.wantNext, nextCalled)
			assert.Equal(t, !tc.wantNext, failureCalled)
		})
	}
}
