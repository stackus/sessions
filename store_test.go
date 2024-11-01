package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCookieStore_Get(t *testing.T) {
	type testCase struct {
		setupProxy  func(proxy *SessionProxy)
		cookieName  string
		cookieValue string
		wantValues  any
		wantIsNew   bool
		wantErr     error
	}

	tests := map[string]testCase{
		"existing_cookie": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.codecs = []Codec{
					&stubCodec{
						decodeFn: func(name string, src []byte, dst any) error {
							*dst.(*string) = string(src)
							return nil
						},
					},
				}
				proxy.options = &CookieOptions{}
				proxy.Values = new(string)
			},
			cookieName:  "session",
			cookieValue: "cookie_value",
			wantValues:  func() *string { v := "cookie_value"; return &v }(),
		},
		"no_codecs": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.options = &CookieOptions{}
				proxy.Values = new(string)
			},
			cookieName: "session",
			wantErr:    ErrNoCodecs,
		},
		"invalid_codec": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.codecs = []Codec{
					&stubCodec{
						decodeFn: func(name string, src []byte, dst any) error {
							return assert.AnError
						},
					},
				}
				proxy.options = &CookieOptions{}
				proxy.Values = new(string)
			},
			cookieName:  "session",
			cookieValue: "cookie_value",
			wantErr:     assert.AnError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := CookieStore{}

			// Act
			err := store.Get(req.Context(), proxy, tc.cookieValue)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantIsNew, proxy.IsNew)
				assert.Equal(t, tc.wantValues, proxy.Values)
			}
		})
	}
}

func TestCookieStore_New(t *testing.T) {
	type testCase struct {
		setupProxy  func(proxy *SessionProxy)
		cookieName  string
		cookieValue string
		wantValues  any
		wantIsNew   bool
		wantErr     error
	}

	tests := map[string]testCase{
		"new_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = new(string)
				proxy.IsNew = true
			},
			cookieName: "session",
			wantValues: func() *string { v := new(string); *v = ""; return v }(),
			wantIsNew:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := CookieStore{}

			// Act
			err := store.New(req.Context(), proxy)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantIsNew, proxy.IsNew)
				assert.Equal(t, tc.wantValues, proxy.Values)
			}
		})
	}
}

func TestCookieStore_Save(t *testing.T) {
	type testCase struct {
		setupProxy  func(proxy *SessionProxy)
		cookieName  string
		cookieValue string
		wantCookies []*http.Cookie
		wantErr     error
	}

	tests := map[string]testCase{
		"new_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = func() *string { v := new(string); *v = "cookie_value"; return v }()
				proxy.options = &CookieOptions{
					MaxAge: 3600,
				}
				proxy.codecs = []Codec{
					&stubCodec{
						encodeFn: func(name string, src any) ([]byte, error) {
							return []byte(*src.(*string)), nil
						},
					},
				}
			},
			cookieName: "session",
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "cookie_value",
					MaxAge: 3600,
				},
			},
		},
		"no_codecs": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = func() *string { v := new(string); *v = "cookie_value"; return v }()
				proxy.options = &CookieOptions{}
			},
			cookieName: "session",
			wantErr:    ErrNoCodecs,
		},
		"deleted_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = func() *string { v := new(string); *v = "cookie_value"; return v }()
				proxy.options = &CookieOptions{
					MaxAge: -1,
				}
				proxy.codecs = []Codec{
					&stubCodec{
						encodeFn: func(name string, src any) ([]byte, error) {
							return []byte(*src.(*string)), nil
						},
					},
				}
			},
			cookieName: "session",
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
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := CookieStore{}

			// Act
			err := store.Save(req.Context(), proxy)

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

func TestFileSystemStore_Get(t *testing.T) {
	type testCase struct {
		setupProxy func(proxy *SessionProxy)
		setupFile  func(store *FileSystemStore, proxy *SessionProxy, id string) error
		cookieName string
		cookieID   string
		maxLength  int
		wantValues any
		wantIsNew  bool
		wantErr    error
	}

	var codecKey = RandomBytes(32)

	type testValues struct {
		Value string
	}

	tests := map[string]testCase{
		"existing_cookie": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.options = &CookieOptions{
					MaxAge: 3600,
				}
				proxy.codecs = []Codec{
					NewCodec(codecKey),
				}
				proxy.Values = new(testValues)
			},
			setupFile: func(store *FileSystemStore, proxy *SessionProxy, id string) error {
				v := &testValues{Value: "cookie_value"}
				data, err := proxy.Encode(v)
				if err != nil {
					return err
				}
				return store.write(store.fileName(id), data)
			},
			cookieName: "session",
			cookieID:   "cookie_id",
			wantValues: &testValues{Value: "cookie_value"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			tmpDir := t.TempDir()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := NewFileSystemStore(tmpDir, tc.maxLength)
			if tc.setupFile != nil {
				err := tc.setupFile(store, proxy, tc.cookieID)
				assert.NoError(t, err)
			}
			cookieValue, _ := proxy.Encode(tc.cookieID)

			// Act
			err := store.Get(req.Context(), proxy, string(cookieValue))

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantIsNew, proxy.IsNew)
				assert.Equal(t, tc.wantValues, proxy.Values)
			}
		})
	}
}

func TestFileSystemStore_New(t *testing.T) {
	type testCase struct {
		setupProxy func(proxy *SessionProxy)
		cookieName string
		cookieID   string
		maxLength  int
		wantValues any
		wantIsNew  bool
		wantErr    error
	}

	type testValues struct {
		Value string
	}

	tests := map[string]testCase{
		"new_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = new(testValues)
				proxy.IsNew = true
			},
			cookieName: "session",
			wantValues: &testValues{Value: ""},
			wantIsNew:  true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			tmpDir := t.TempDir()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := NewFileSystemStore(tmpDir, tc.maxLength)

			// Act
			err := store.New(req.Context(), proxy)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantIsNew, proxy.IsNew)
				assert.Equal(t, tc.wantValues, proxy.Values)
			}
		})
	}
}

func TestFileSystemStore_Save(t *testing.T) {
	type testCase struct {
		setupProxy  func(proxy *SessionProxy)
		setupFile   func(store *FileSystemStore, proxy *SessionProxy, id string) error
		cookieName  string
		cookieID    string
		maxLength   int
		wantCookies []*http.Cookie
		wantErr     error
	}

	var codecKey = RandomBytes(32)

	type testValues struct {
		Value string
	}

	tests := map[string]testCase{
		"existing_cookie": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.ID = "cookie_id"
				proxy.Values = &testValues{Value: "cookie_value"}
				proxy.options = &CookieOptions{
					MaxAge: 3600,
				}
				proxy.codecs = []Codec{
					NewCodec(codecKey),
				}
				proxy.Values = new(testValues)
			},
			setupFile: func(store *FileSystemStore, proxy *SessionProxy, id string) error {
				v := &testValues{Value: "cookie_value"}
				data, err := proxy.Encode(v)
				if err != nil {
					return err
				}
				return store.write(store.fileName(id), data)
			},
			cookieName: "session",
			cookieID:   "cookie_id",
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "cookie_id",
					MaxAge: 3600,
				},
			},
		},
		"new_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.Values = &testValues{Value: "cookie_value"}
				proxy.options = &CookieOptions{
					MaxAge: 3600,
				}
				proxy.codecs = []Codec{
					NewCodec(codecKey),
				}
			},
			cookieName: "session",
			cookieID:   "cookie_id",
			wantCookies: []*http.Cookie{
				{
					Name:   "session",
					Value:  "cookie_id",
					MaxAge: 3600,
				},
			},
		},
		"deleted_session": {
			setupProxy: func(proxy *SessionProxy) {
				proxy.ID = "cookie_id"
				proxy.Values = &testValues{Value: "cookie_value"}
				proxy.options = &CookieOptions{
					MaxAge: -1,
				}
				proxy.codecs = []Codec{
					NewCodec(codecKey),
				}
			},
			cookieName: "session",
			cookieID:   "cookie_id",
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
			tmpDir := t.TempDir()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			resp := httptest.NewRecorder()
			proxy := &SessionProxy{
				req:        req,
				resp:       resp,
				cookieName: tc.cookieName,
			}
			if tc.setupProxy != nil {
				tc.setupProxy(proxy)
			}
			store := NewFileSystemStore(tmpDir, tc.maxLength)
			if tc.setupFile != nil {
				err := tc.setupFile(store, proxy, tc.cookieID)
				assert.NoError(t, err)
			}

			// Act
			err := store.Save(req.Context(), proxy)

			// Assert
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, len(tc.wantCookies), len(resp.Result().Cookies()))
				if len(tc.wantCookies) > 0 {
					want := tc.wantCookies[0]
					got := resp.Result().Cookies()[0]
					cookieValue := []byte{}
					if want.Value != "" {
						cookieValue, _ = proxy.Encode(proxy.ID)
					}
					assert.Equal(t, want.Name, got.Name)
					assert.Equal(t, string(cookieValue), got.Value)
					assert.Equal(t, want.MaxAge, got.MaxAge)
				}
			}
		})
	}
}
