package sessions

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type app struct {
	manager *Manager[testSession]
	handler http.Handler
}

func newApp(m *Manager[testSession]) *app {
	mux := http.NewServeMux()

	fail := func(w http.ResponseWriter, err error) {
		http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
	}

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.Load(r); err != nil && !IsNoSession(err) {
			fail(w, err)
			return
		}
		sess, err := m.New(r, testSession{UserID: 7, Roles: []string{"user"}})
		if err == nil {
			err = sess.Save(w)
		}
		if err != nil {
			fail(w, err)
			return
		}
		_, _ = io.WriteString(w, "logged in")
	})
	mux.HandleFunc("POST /promote", func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.Load(r)
		if err == nil {
			err = sess.Update(func(v *testSession) { v.Roles = append(v.Roles, "admin") })
		}
		if err == nil {
			err = sess.Save(w)
		}
		if err != nil {
			fail(w, err)
			return
		}
		_, _ = io.WriteString(w, "promoted")
	})
	mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.Load(r)
		if IsNoSession(err) {
			_, _ = io.WriteString(w, "anonymous")
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		v := sess.Values()
		_, _ = fmt.Fprintf(w, "user %d %s", v.UserID, strings.Join(v.Roles, ","))
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		if err := m.Delete(w, r); err != nil {
			fail(w, err)
			return
		}
		_, _ = io.WriteString(w, "logged out")
	})
	return &app{manager: m, handler: m.Middleware()(mux)}
}

type browser struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func newBrowser(t *testing.T, handler http.Handler) *browser {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, server: server, client: &http.Client{Jar: jar}}
}

func (b *browser) do(method, path string) (int, string) {
	b.t.Helper()
	req, err := http.NewRequest(method, b.server.URL+path, nil)
	require.NoError(b.t, err)
	resp, err := b.client.Do(req)
	require.NoError(b.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(b.t, err)
	return resp.StatusCode, strings.TrimSpace(string(body))
}

func (b *browser) cookie() string {
	b.t.Helper()
	u, err := url.Parse(b.server.URL)
	require.NoError(b.t, err)
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == "session" {
			return c.Value
		}
	}
	return ""
}

func (b *browser) setCookie(value string) {
	b.t.Helper()
	u, err := url.Parse(b.server.URL)
	require.NoError(b.t, err)
	b.client.Jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: value, Path: "/"}})
}

func newCookieManager(t *testing.T, encoder Encoder, store Store, opts ...ManagerOption) *Manager[testSession] {
	t.Helper()
	transport, err := NewCookieTransport("session", CookieTransportSecure(false))
	require.NoError(t, err)
	m, err := NewManager[testSession](transport, encoder, store, opts...)
	require.NoError(t, err)
	return m
}

func newFileStoreIn(t *testing.T, dir string) *FileStore {
	t.Helper()
	store, err := NewFileStore(dir)
	require.NoError(t, err)
	return store
}

func TestAcceptance_Configurations(t *testing.T) {
	hmacEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	aesEnc, err := NewAESGCMEncoder(randomBytes(t, 32))
	require.NoError(t, err)

	configs := map[string]func(t *testing.T, dir string) (Encoder, Store){
		"A: base64 + file store":  func(t *testing.T, dir string) (Encoder, Store) { return NewBase64Encoder(), newFileStoreIn(t, dir) },
		"B: hmac + cookie store":  func(t *testing.T, dir string) (Encoder, Store) { return hmacEnc, NewCookieStore() },
		"D: aes-gcm + file store": func(t *testing.T, dir string) (Encoder, Store) { return aesEnc, newFileStoreIn(t, dir) },
	}
	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			encoder, store := config(t, dir)
			b := newBrowser(t, newApp(newCookieManager(t, encoder, store)).handler)

			code, body := b.do(http.MethodGet, "/me")
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, "anonymous", body)
			assert.Empty(t, b.cookie())
			assert.Equal(t, []string{"."}, dirSnapshot(t, dir), "no record created")

			code, body = b.do(http.MethodPost, "/login")
			require.Equal(t, http.StatusOK, code, body)
			first := b.cookie()
			require.NotEmpty(t, first)

			code, body = b.do(http.MethodPost, "/promote")
			require.Equal(t, http.StatusOK, code, body)
			_, body = b.do(http.MethodGet, "/me")
			assert.Equal(t, "user 7 user,admin", body)
			if _, ok := store.(*FileStore); ok {
				assert.Equal(t, first, b.cookie(), "stable ID not reissued")
			} else {
				assert.NotEqual(t, first, b.cookie(), "stateless credential reissued")
			}

			// Login again rotates the credential and revokes the old record
			// for a revocable store.
			beforeLogin := b.cookie()
			code, body = b.do(http.MethodPost, "/login")
			require.Equal(t, http.StatusOK, code, body)
			assert.NotEqual(t, beforeLogin, b.cookie())
			if _, ok := store.(*FileStore); ok {
				_, err := store.Load(t.Context(), beforeLogin, testStoreParams())
				assert.ErrorIs(t, err, ErrSessionNotFound, "old record deleted")
			}

			code, body = b.do(http.MethodPost, "/logout")
			require.Equal(t, http.StatusOK, code, body)
			assert.Empty(t, b.cookie(), "cookie cleared")
			_, body = b.do(http.MethodGet, "/me")
			assert.Equal(t, "anonymous", body)
			if _, ok := store.(*FileStore); ok {
				assert.Equal(t, []string{"."}, dirSnapshot(t, dir), "no records left")
			}
		})
	}
}

func TestAcceptance_AnonymousRequest(t *testing.T) {
	h := newLoadHarness(t)
	dir := h.store.Store.(*FileStore).dir
	_, rec := h.do(t, cookieRequest(h.issue(t, testSession{UserID: 1})), func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	})
	assert.Empty(t, h.trace.Calls())
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Len(t, dirSnapshot(t, dir), 2, "only the pre-issued record")
}

func TestAcceptance_StaleCookie(t *testing.T) {
	oldEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	newEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)

	oldApp := newBrowser(t, newApp(newCookieManager(t, oldEnc, NewCookieStore())).handler)
	_, _ = oldApp.do(http.MethodPost, "/login")
	stale := oldApp.cookie()
	require.NotEmpty(t, stale)

	b := newBrowser(t, newApp(newCookieManager(t, newEnc, NewCookieStore())).handler)
	b.setCookie(stale)
	code, body := b.do(http.MethodGet, "/me")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "anonymous", body, "no replacement session created")
	assert.Equal(t, stale, b.cookie(), "Load does not erase the cookie by itself")

	code, _ = b.do(http.MethodPost, "/logout")
	assert.Equal(t, http.StatusOK, code)
	assert.Empty(t, b.cookie(), "Delete clears the undecodable cookie")
}

func TestAcceptance_BearerFlowC(t *testing.T) {
	transport, err := NewBearerTransport(BearerTransportTokenHeader("App-Token"))
	require.NoError(t, err)
	m, err := NewManager[testSession](transport, NewBase64Encoder(), newFileStoreIn(t, t.TempDir()))
	require.NoError(t, err)
	server := httptest.NewServer(newApp(m).handler)
	t.Cleanup(server.Close)

	send := func(method, path, token string) *http.Response {
		req, err := http.NewRequest(method, server.URL+path, nil)
		require.NoError(t, err)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	body := func(resp *http.Response) string {
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return strings.TrimSpace(string(b))
	}

	resp := send(http.MethodGet, "/me", "")
	assert.Equal(t, "anonymous", body(resp))
	assert.Empty(t, resp.Header.Get("App-Token"), "no response token without session use")

	resp = send(http.MethodPost, "/login", "")
	token := resp.Header.Get("App-Token")
	require.NotEmpty(t, token)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	resp = send(http.MethodPost, "/promote", token)
	assert.Equal(t, "promoted", body(resp))
	assert.Empty(t, resp.Header.Get("App-Token"), "stable ID not reissued")

	resp = send(http.MethodGet, "/me", token)
	assert.Equal(t, "user 7 user,admin", body(resp))

	resp = send(http.MethodPost, "/logout", token)
	assert.Equal(t, "clear", resp.Header.Get("App-Token-Action"))
	resp = send(http.MethodGet, "/me", token)
	assert.Equal(t, "anonymous", body(resp), "the deleted token no longer works")
}

func TestAcceptance_InsecureConfigE(t *testing.T) {
	b := newBrowser(t, newApp(newCookieManager(t, NewBase64Encoder(), NewCookieStore())).handler)
	_, _ = b.do(http.MethodPost, "/login")
	cookie := b.cookie()
	require.NotEmpty(t, cookie)

	// Decode the two base64 layers (CookieStore, then Base64Encoder), change
	// the user, and re-encode.
	record, err := base64.RawURLEncoding.DecodeString(cookie)
	require.NoError(t, err)
	payload, err := base64.RawURLEncoding.DecodeString(string(record))
	require.NoError(t, err)
	forged := strings.Replace(string(payload), `"user_id":7`, `"user_id":1`, 1)
	require.NotEqual(t, string(payload), forged)
	b.setCookie(base64.RawURLEncoding.EncodeToString([]byte(base64.RawURLEncoding.EncodeToString([]byte(forged)))))

	_, body := b.do(http.MethodGet, "/me")
	assert.Equal(t, "user 1 user", body, "forgery accepted: this configuration must not be used")
}

// HMAC authenticates the expiry as well as the values: a client cannot extend
// a CookieStore session.
func TestAcceptance_HMACProtectsExpiry(t *testing.T) {
	hmacEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	b := newBrowser(t, newApp(newCookieManager(t, hmacEnc, NewCookieStore())).handler)
	_, _ = b.do(http.MethodPost, "/login")

	record, err := base64.RawURLEncoding.DecodeString(b.cookie())
	require.NoError(t, err)
	payload := record[1 : len(record)-32] // HMAC format: version || payload || tag
	var env envelope
	require.NoError(t, json.Unmarshal(payload, &env))
	env.ExpiresAt += 365 * 24 * 60 * 60
	extended, err := json.Marshal(env)
	require.NoError(t, err)
	tampered := append(append([]byte{record[0]}, extended...), record[len(record)-32:]...)
	b.setCookie(base64.RawURLEncoding.EncodeToString(tampered))

	_, body := b.do(http.MethodGet, "/me")
	assert.Equal(t, "anonymous", body, "tampered expiry rejected")
}

// Key rotation across deployments: a record from the old key loads under a
// rotating encoder, is re-encoded on Save, and then loads with the new key
// alone.
func TestAcceptance_KeyRotationAcrossManagers(t *testing.T) {
	oldKey, err := NewAESGCMEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	newKey, err := NewAESGCMEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	rotating, err := NewRotatingEncoder(newKey, oldKey)
	require.NoError(t, err)
	dir := t.TempDir()

	before := newBrowser(t, newApp(newCookieManager(t, oldKey, newFileStoreIn(t, dir))).handler)
	_, _ = before.do(http.MethodPost, "/login")
	credential := before.cookie()
	require.NotEmpty(t, credential)

	// Deploy with the rotating encoder; any Save re-encodes, even without
	// value changes.
	m := newCookieManager(t, rotating, newFileStoreIn(t, dir))
	refresh := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.Load(r)
		require.NoError(t, err)
		assert.False(t, sess.IsDirty())
		require.NoError(t, sess.Save(w))
	}))
	rec := httptest.NewRecorder()
	refresh.ServeHTTP(rec, cookieRequest(credential))
	assert.Empty(t, rec.Header().Values("Set-Cookie"), "stable ID not reissued")

	// Retire the old key entirely.
	after := newBrowser(t, newApp(newCookieManager(t, newKey, newFileStoreIn(t, dir))).handler)
	after.setCookie(credential)
	_, body := after.do(http.MethodGet, "/me")
	assert.Equal(t, "user 7 user", body)
}

func TestAcceptance_SaveBeforeResponseReachesClient(t *testing.T) {
	hmacEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	m := newCookieManager(t, hmacEnc, NewCookieStore(), WithMaxRecordSize(256))

	handler := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		roles := []string{"user"}
		if r.URL.Query().Has("big") {
			roles = []string{strings.Repeat("x", 200)}
		}
		sess, err := m.New(r, testSession{UserID: 1, Roles: roles})
		require.NoError(t, err)
		if err := sess.Save(w); err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		_, _ = io.WriteString(w, "saved")
	}))
	b := newBrowser(t, handler)

	code, body := b.do(http.MethodGet, "/")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, "saved", body)
	assert.NotEmpty(t, b.cookie())

	b.setCookie("")
	code, body = b.do(http.MethodGet, "/?big")
	assert.Equal(t, http.StatusInternalServerError, code, "the handler saw the Save failure")
	assert.Equal(t, "Internal Server Error", body)
}

func TestAcceptance_ReplacedSessionMethods(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})
	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		loaded, err := h.manager.Load(r)
		require.NoError(t, err)
		_, err = h.manager.New(r)
		require.NoError(t, err)
		assert.ErrorIs(t, loaded.Set(testSession{}), ErrSessionReplaced)
		assert.ErrorIs(t, loaded.Update(func(*testSession) {}), ErrSessionReplaced)
		assert.ErrorIs(t, loaded.Save(w), ErrSessionReplaced)
		assert.ErrorIs(t, loaded.Delete(w), ErrSessionReplaced)
	})
}

// Every exported error path reports its classification, and no message, public
// or diagnostic, leaks a credential, a key, or a session value.
func TestAcceptance_ErrorSurface(t *testing.T) {
	const secretValue = "s3cr3t-role-value"
	key := randomBytes(t, 32)

	type errorCase struct {
		err      func(t *testing.T, h *testHarness, credential string) error
		want     error
		typeCode string
		httpCode int
	}
	inRequest := func(t *testing.T, h *testHarness, r *http.Request, fn func(w http.ResponseWriter, r *http.Request) error) error {
		var err error
		h.do(t, r, func(w http.ResponseWriter, r *http.Request) { err = fn(w, r) })
		return err
	}
	load := func(t *testing.T, h *testHarness, r *http.Request) error {
		return inRequest(t, h, r, func(_ http.ResponseWriter, r *http.Request) error {
			_, err := h.manager.Load(r)
			return err
		})
	}
	committed := func(t *testing.T, h *testHarness, credential string) *Session[testSession] {
		var sess *Session[testSession]
		h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
			var err error
			sess, err = h.manager.Load(r)
			require.NoError(t, err)
			require.NoError(t, sess.Save(w))
		})
		return sess
	}

	cases := map[string]errorCase{
		"Load: no scope": {
			err: func(t *testing.T, h *testHarness, c string) error {
				_, err := h.manager.Load(cookieRequest(c))
				return err
			},
			want: ErrNoScope, typeCode: "SESSION_NO_SCOPE", httpCode: 500,
		},
		"Load: no session": {
			err:  func(t *testing.T, h *testHarness, c string) error { return load(t, h, cookieRequest()) },
			want: ErrNoSession, typeCode: "SESSION_NONE", httpCode: 401,
		},
		"Load: invalid": {
			err:  func(t *testing.T, h *testHarness, c string) error { return load(t, h, cookieRequest(c+"x")) },
			want: ErrInvalidSession, typeCode: "SESSION_INVALID", httpCode: 401,
		},
		"Load: tampered": {
			err: func(t *testing.T, h *testHarness, c string) error {
				record, err := h.store.Store.Load(t.Context(), c, testStoreParams())
				require.NoError(t, err)
				record[5] ^= 1
				_, err = h.store.Store.Update(t.Context(), c, record, testStoreParams())
				require.NoError(t, err)
				return load(t, h, cookieRequest(c))
			},
			want: ErrInvalidSession, typeCode: "SESSION_INVALID", httpCode: 401,
		},
		"Load: not found": {
			err: func(t *testing.T, h *testHarness, c string) error {
				require.NoError(t, h.store.Store.Delete(t.Context(), c))
				return load(t, h, cookieRequest(c))
			},
			want: ErrSessionNotFound, typeCode: "SESSION_NOT_FOUND", httpCode: 401,
		},
		"Load: expired": {
			err: func(t *testing.T, h *testHarness, c string) error {
				h.manager.now = func() time.Time { return loadTestNow.Add(24 * time.Hour) }
				return load(t, h, cookieRequest(c))
			},
			want: ErrSessionExpired, typeCode: "SESSION_EXPIRED", httpCode: 401,
		},
		"Load: deleted": {
			err: func(t *testing.T, h *testHarness, c string) error {
				return inRequest(t, h, cookieRequest(c), func(w http.ResponseWriter, r *http.Request) error {
					require.NoError(t, h.manager.Delete(w, r))
					_, err := h.manager.Load(r)
					return err
				})
			},
			want: ErrSessionDeleted, typeCode: "SESSION_DELETED", httpCode: 401,
		},
		"Load: store failure": {
			err: func(t *testing.T, h *testHarness, c string) error {
				h.store.FailWith("Load", errors.ErrUnavailable.Msg("database unreachable"))
				return load(t, h, cookieRequest(c))
			},
			want: errors.ErrUnavailable, typeCode: "UNAVAILABLE", httpCode: 503,
		},
		"New: no scope": {
			err: func(t *testing.T, h *testHarness, c string) error {
				_, err := h.manager.New(cookieRequest(c))
				return err
			},
			want: ErrNoScope, typeCode: "SESSION_NO_SCOPE", httpCode: 500,
		},
		"New: too many values": {
			err: func(t *testing.T, h *testHarness, c string) error {
				return inRequest(t, h, cookieRequest(c), func(_ http.ResponseWriter, r *http.Request) error {
					_, err := h.manager.New(r, testSession{Roles: []string{secretValue}}, testSession{})
					return err
				})
			},
			want: errors.ErrInvalidArgument, typeCode: "INVALID_ARGUMENT", httpCode: 400,
		},
		"Delete: no scope": {
			err: func(t *testing.T, h *testHarness, c string) error {
				return h.manager.Delete(httptest.NewRecorder(), cookieRequest(c))
			},
			want: ErrNoScope, typeCode: "SESSION_NO_SCOPE", httpCode: 500,
		},
		"Set: committed": {
			err:  func(t *testing.T, h *testHarness, c string) error { return committed(t, h, c).Set(testSession{}) },
			want: ErrSessionCommitted, typeCode: "SESSION_COMMITTED", httpCode: 500,
		},
		"Delete: committed": {
			err: func(t *testing.T, h *testHarness, c string) error {
				return committed(t, h, c).Delete(httptest.NewRecorder())
			},
			want: ErrSessionCommitted, typeCode: "SESSION_COMMITTED", httpCode: 500,
		},
		"Save: store failure": {
			err: func(t *testing.T, h *testHarness, c string) error {
				h.store.FailWith("Update", errors.ErrInternal.Msg("disk full"))
				return inRequest(t, h, cookieRequest(c), func(w http.ResponseWriter, r *http.Request) error {
					sess, err := h.manager.Load(r)
					require.NoError(t, err)
					require.NoError(t, sess.Update(func(v *testSession) { v.UserID++ }))
					return sess.Save(w)
				})
			},
			want: errors.ErrInternal, typeCode: "INTERNAL", httpCode: 500,
		},
		"NewHMACEncoder: short key": {
			err:  func(t *testing.T, h *testHarness, c string) error { _, err := NewHMACEncoder(key[:16]); return err },
			want: errors.ErrInvalidArgument, typeCode: "INVALID_ARGUMENT", httpCode: 400,
		},
		"NewAESGCMEncoder: bad key": {
			err:  func(t *testing.T, h *testHarness, c string) error { _, err := NewAESGCMEncoder(key[:20]); return err },
			want: errors.ErrInvalidArgument, typeCode: "INVALID_ARGUMENT", httpCode: 400,
		},
		"Encoder.Decode: foreign": {
			err: func(t *testing.T, h *testHarness, c string) error {
				enc, err := NewHMACEncoder(key)
				require.NoError(t, err)
				_, err = enc.Decode([]byte(c + strings.Repeat("0", 40)))
				return err
			},
			want: ErrInvalidEncoding, typeCode: "SESSION_INVALID_ENCODING", httpCode: 400,
		},
		"Transport.Read: no credential": {
			err: func(t *testing.T, h *testHarness, c string) error {
				_, err := h.transport.Transport.Read(cookieRequest())
				return err
			},
			want: ErrNoCredential, typeCode: "SESSION_NO_CREDENTIAL", httpCode: 401,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			credential := h.issue(t, testSession{UserID: 1, Roles: []string{secretValue}})

			err := tc.err(t, h, credential)
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.want)
			assert.Equal(t, tc.typeCode, errors.TypeCode(err))
			assert.Equal(t, tc.httpCode, errors.HTTPCode(err))

			public := errors.PublicMessage(err)
			for _, message := range []string{err.Error(), public} {
				assert.NotContains(t, message, credential, "credential leaked")
				assert.NotContains(t, message, secretValue, "session value leaked")
				assert.NotContains(t, message, string(key), "key leaked")
				assert.NotContains(t, message, base64.RawURLEncoding.EncodeToString(key), "key leaked")
			}
			assert.NotContains(t, public, "unreachable", "internal detail in public message")
			assert.NotContains(t, public, "disk", "internal detail in public message")
		})
	}
}

// Many concurrent requests through one manager (run with -race).
func TestAcceptance_ConcurrentRequests(t *testing.T) {
	m := newCookieManager(t, NewBase64Encoder(), newFileStoreIn(t, t.TempDir()))
	a := newApp(m)
	server := httptest.NewServer(a.handler)
	t.Cleanup(server.Close)

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			jar, err := cookiejar.New(nil)
			if !assert.NoError(t, err) {
				return
			}
			client := &http.Client{Jar: jar}
			for _, step := range []struct{ method, path, want string }{
				{http.MethodPost, "/login", "logged in"},
				{http.MethodPost, "/promote", "promoted"},
				{http.MethodGet, "/me", "user 7 user,admin"},
				{http.MethodPost, "/logout", "logged out"},
				{http.MethodGet, "/me", "anonymous"},
			} {
				req, err := http.NewRequest(step.method, server.URL+step.path, nil)
				if !assert.NoError(t, err) {
					return
				}
				resp, err := client.Do(req)
				if !assert.NoError(t, err) {
					return
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				assert.Equal(t, step.want, strings.TrimSpace(string(body)))
			}
		})
	}
	wg.Wait()
}

// Coverage for commit paths not reached elsewhere.
func TestAcceptance_SaveOperationalPaths(t *testing.T) {
	t.Run("payload over limit", func(t *testing.T) {
		h := newLoadHarness(t, WithMaxPayloadSize(32))
		h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
			sess, err := h.manager.New(r, testSession{UserID: 1, Roles: []string{"a long role name"}})
			require.NoError(t, err)
			err = sess.Save(w)
			require.Error(t, err)
			assert.False(t, IsNoSession(err))
			assert.False(t, sess.committed)
		})
		assert.Empty(t, h.store.Calls())
	})
	t.Run("encode fails during update", func(t *testing.T) {
		h := newLoadHarness(t)
		credential := h.issue(t, testSession{UserID: 1})
		h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
			sess, err := h.manager.Load(r)
			require.NoError(t, err)
			require.NoError(t, sess.Set(testSession{UserID: 2}))
			h.encoder.FailWith("Encode", errors.ErrInternal.Msg("key service down"))
			require.Error(t, sess.Save(w))
			assert.True(t, sess.IsDirty())
		})
		assert.Equal(t, []string{"Load"}, h.store.Calls())
	})
}
