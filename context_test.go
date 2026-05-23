package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreAndFromContext(t *testing.T) {
	type accessData struct{ UserID int }

	type testCase struct {
		setupReq   func(r *http.Request) *http.Request
		cookieName string
		wantErr    error
		wantUserID int
	}

	tests := map[string]testCase{
		"retrieves_stored_session": {
			setupReq: func(r *http.Request) *http.Request {
				session := &Session[accessData]{Values: accessData{UserID: 42}}
				return StoreInContext(r, "access", session)
			},
			cookieName: "access",
			wantUserID: 42,
		},
		"returns_error_when_not_found": {
			setupReq:   func(r *http.Request) *http.Request { return r },
			cookieName: "access",
			wantErr:    ErrSessionNotFound,
		},
		"different_cookie_names_are_independent": {
			setupReq: func(r *http.Request) *http.Request {
				session := &Session[accessData]{Values: accessData{UserID: 99}}
				return StoreInContext(r, "refresh", session) // stored under "refresh"
			},
			cookieName: "access", // looking for "access"
			wantErr:    ErrSessionNotFound,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = tc.setupReq(r)

			// Act
			got, err := FromContext[accessData](r, tc.cookieName)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantUserID, got.Values.UserID)
			}
		})
	}
}
