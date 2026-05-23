package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSaveMiddleware(t *testing.T) {
	type testCase struct {
		setupInner func(mgr SessionManager[string]) http.HandlerFunc
		cookieName string
		wantCookie bool
	}

	tests := map[string]testCase{
		"session_saved_automatically_after_inner_handler": {
			cookieName: "test_session",
			setupInner: func(mgr SessionManager[string]) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					session, err := mgr.Get(r)
					assert.NoError(t, err)
					session.Values = "hello"
					// deliberately do NOT call session.Save — middleware should do it
				}
			},
			wantCookie: true,
		},
		"no_sessions_registered_is_noop": {
			cookieName: "test_session",
			setupInner: func(mgr SessionManager[string]) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					// do nothing — no sessions registered
				}
			},
			wantCookie: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			codec := &stubCodec{
				encodeFn: func(name string, src any) ([]byte, error) {
					return []byte("encoded_value"), nil
				},
				decodeFn: func(name string, src []byte, dst any) error {
					return nil
				},
			}
			mgr := NewSessionManager[string](
				NewCookieOptions(tc.cookieName),
				CookieStore{},
				[]Codec{codec},
			)
			handler := SaveMiddleware(tc.setupInner(mgr))
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/", nil)

			// Act
			handler.ServeHTTP(w, r)

			// Assert
			cookies := w.Result().Cookies()
			var found bool
			for _, c := range cookies {
				if c.Name == tc.cookieName {
					found = true
					break
				}
			}
			assert.Equal(t, tc.wantCookie, found)
		})
	}
}
