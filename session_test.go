package sessions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSession(t *testing.T) {
	type sessionData struct {
		Value string
	}

	type testCase struct {
		options      CookieOptions
		store        Store
		codecs       []Codec
		setupReq     func(r *http.Request)
		setupSession func(s *Session[sessionData])
		wantCookies  []*http.Cookie
		wantErr      error
	}

	tests := map[string]testCase{
		"save_session": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "new-value"
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  base64.StdEncoding.EncodeToString([]byte(`{"Value":"new-value"}`)),
					MaxAge: 3600,
				},
			},
		},
		"save_session_no_cookie": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "session-value"
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  base64.StdEncoding.EncodeToString([]byte(`{"Value":"session-value"}`)),
					MaxAge: 3600,
				},
			},
		},
		"save_session_error": {
			options: CookieOptions{
				MaxAge: 3600,
			},
			store: &stubStore{
				getFn: func(ctx context.Context, proxy *SessionProxy, cookieValue string) error {
					return proxy.Decode([]byte(cookieValue), proxy.Values)
				},
				saveFn: func(ctx context.Context, proxy *SessionProxy) error {
					return assert.AnError
				},
			},
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
			wantErr: assert.AnError,
		},
		"expire_session": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Expire()
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "",
					MaxAge: -1,
				},
			},
		},
		"remember_me": {
			options: CookieOptions{
				MaxAge: 0,
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "session-value"
				s.Persist(3600)
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  base64.StdEncoding.EncodeToString([]byte(`{"Value":"session-value"}`)),
					MaxAge: 3600,
				},
			},
		},
		"do_not_remember_me": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "session-value"
				s.DoNotPersist()
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  base64.StdEncoding.EncodeToString([]byte(`{"Value":"session-value"}`)),
					MaxAge: 0,
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

			session, _ := manager.Get(req, "session")
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

func TestSession_Delete(t *testing.T) {
	type sessionData struct {
		Value string
	}

	type testCase struct {
		options      CookieOptions
		store        Store
		codecs       []Codec
		setupReq     func(r *http.Request)
		setupSession func(s *Session[sessionData])
		wantCookies  []*http.Cookie
		wantErr      error
	}

	tests := map[string]testCase{
		"delete_session": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "new-value"
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "",
					MaxAge: -1,
				},
			},
		},
		"delete_session_no_cookie": {
			options: CookieOptions{
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
			setupSession: func(s *Session[sessionData]) {
				s.Values.Value = "session-value"
			},
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "",
					MaxAge: -1,
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

			session, _ := manager.Get(req, "session")
			if tc.setupSession != nil {
				tc.setupSession(session)
			}

			resp := httptest.NewRecorder()

			// Act
			err := session.Delete(resp, req)

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
