package sessions

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSessionManager_Get(t *testing.T) {
	type sessionData struct {
		UserID   int
		Username string
	}

	cookieName := "session"

	type testCase[T any] struct {
		store      func() *mockStore
		codec      func() *mockCodec
		setupReq   func(r *http.Request)
		wantValues T
		wantIsNew  bool
		wantErr    error
	}
	tests := map[string]testCase[sessionData]{
		"new_session": {
			store: func() *mockStore {
				store := &mockStore{}
				store.
					On("New", mock.Anything, mock.AnythingOfType("*sessions.SessionProxy")).
					Run(func(args mock.Arguments) {
						proxy := args.Get(1).(*SessionProxy)
						proxy.IsNew = true
					}).
					Return(nil)
				return store
			},
			codec: func() *mockCodec {
				return &mockCodec{}
			},
			wantValues: sessionData{},
			wantIsNew:  true,
		},
		"existing_session": {
			store: func() *mockStore {
				store := &mockStore{}
				store.
					On("Get", mock.Anything, mock.AnythingOfType("*sessions.SessionProxy"), "cookie_value").
					Run(func(args mock.Arguments) {
						proxy := args.Get(1).(*SessionProxy)
						_ = proxy.Decode([]byte("cookie_value"), proxy.Values)
					}).
					Return(nil)
				return store
			},
			codec: func() *mockCodec {
				codec := &mockCodec{}
				codec.
					On("Decode", cookieName, []byte("cookie_value"), mock.AnythingOfType("*sessions.sessionData")).
					Run(func(args mock.Arguments) {
						dst := args.Get(2).(*sessionData)
						*dst = sessionData{
							UserID:   1,
							Username: "user",
						}
					}).
					Return(nil)
				return codec
			},
			setupReq: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  cookieName,
					Value: "cookie_value",
				})
			},
			wantValues: sessionData{
				UserID:   1,
				Username: "user",
			},
			wantIsNew: false,
		},
		"invalid_session_value": {
			store: func() *mockStore {
				store := &mockStore{}
				store.
					On("Get", mock.Anything, mock.AnythingOfType("*sessions.SessionProxy"), "cookie_value").
					Run(func(args mock.Arguments) {
						proxy := args.Get(1).(*SessionProxy)
						// Decode an invalid value to the proxy
						proxy.Values = []string{"invalid"}
					}).
					Return(nil)
				return store
			},
			codec: func() *mockCodec {
				return &mockCodec{}
			},
			setupReq: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  cookieName,
					Value: "cookie_value",
				})
			},
			wantErr: ErrInvalidSessionType,
		},
		"store_error": {
			store: func() *mockStore {
				store := &mockStore{}
				store.
					On("New", mock.Anything, mock.AnythingOfType("*sessions.SessionProxy")).
					Return(assert.AnError)
				return store
			},
			codec: func() *mockCodec {
				return &mockCodec{}
			},
			wantErr: assert.AnError,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			store := tc.store()
			codec := tc.codec()

			manager := NewSessionManager[sessionData](
				CookieOptions{
					Name: cookieName,
				},
				store,
				codec,
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.setupReq != nil {
				tc.setupReq(req)
			}

			// Act
			session, err := manager.Get(req)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.Equal(t, tc.wantIsNew, session.IsNew)
				assert.Equal(t, tc.wantValues, session.Values)
			}

			// Verify all mocked calls were made
			store.AssertExpectations(t)
			codec.AssertExpectations(t)
		})
	}
}

func TestSessionManager_Save(t *testing.T) {
	type sessionData struct {
		Value string
	}

	type testCase[T any] struct {
		options      CookieOptions
		store        Store
		codecs       []Codec
		setupReq     func(r *http.Request)
		setupSession func(s *Session[T])
		wantCookies  []*http.Cookie
		wantErr      error
	}

	tests := map[string]testCase[sessionData]{
		"save_session": {
			options: CookieOptions{
				Name:   "session",
				MaxAge: 3600,
			},
			store: CookieStore{},
			codecs: []Codec{
				&stubCodec{
					encodeFn: func(name string, src any) ([]byte, error) {
						b, err := json.Marshal(src)
						if err != nil {
							return nil, err
						}
						return []byte(base64.StdEncoding.EncodeToString(b)), nil
					},
					decodeFn: func(name string, data []byte, dst any) error {
						b, err := base64.StdEncoding.DecodeString(string(data))
						if err != nil {
							return err
						}
						return json.Unmarshal(b, dst)
					},
				},
			},
			setupReq: func(r *http.Request) {
				r.AddCookie(&http.Cookie{
					Name:  "session",
					Value: base64.StdEncoding.EncodeToString([]byte(`{"Value":"session-value"}`)),
				})
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  base64.StdEncoding.EncodeToString([]byte(`{"Value":"session-value"}`)),
					MaxAge: 3600,
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			manager := NewSessionManager[sessionData](
				tc.options,
				tc.store,
				tc.codecs...,
			)

			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.setupReq != nil {
				tc.setupReq(req)
			}

			session, _ := manager.Get(req)
			if tc.setupSession != nil {
				tc.setupSession(session)
			}

			resp := httptest.NewRecorder()

			// Act
			err := session.Save(resp, req)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tc.wantCookies), len(resp.Result().Cookies()))
				if len(tc.wantCookies) > 0 {
					want := tc.wantCookies[0]
					got := resp.Result().Cookies()[0]
					assert.Equal(t, want.Name, got.Name)
					assert.Equal(t, want.Value, got.Value)
					assert.Equal(t, want.MaxAge, got.MaxAge)
				}
			}
		})
	}
}
