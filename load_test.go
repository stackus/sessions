package sessions

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var loadTestNow = time.Unix(1_750_000_000, 0)

// newLoadHarness returns a harness whose clock is fixed at loadTestNow.
func newLoadHarness(t *testing.T, opts ...ManagerOption) *testHarness {
	t.Helper()
	h := newTestHarness(t, opts...)
	h.manager.now = func() time.Time { return loadTestNow }
	return h
}

// issueWith builds a real record for values with encoder and stores it,
// bypassing the recording wrappers. It returns the credential.
func (h *testHarness) issueWith(t *testing.T, encoder Encoder, values testSession, meta envelopeMeta) string {
	t.Helper()
	payload, err := marshalEnvelope(values, meta, defaultMaxPayloadSize)
	require.NoError(t, err)
	record, err := encoder.Encode(payload)
	require.NoError(t, err)
	credential, err := h.store.Store.Create(t.Context(), record, testStoreParams())
	require.NoError(t, err)
	return credential
}

func (h *testHarness) issue(t *testing.T, values testSession) string {
	t.Helper()
	return h.issueWith(t, h.encoder.Encoder, values, envelopeMeta{
		CreatedAt: loadTestNow.Add(-time.Hour),
		ExpiresAt: loadTestNow.Add(time.Hour),
	})
}

// cookieRequest returns a request presenting each value as a session cookie.
func cookieRequest(values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, v := range values {
		r.AddCookie(&http.Cookie{Name: "session", Value: v})
	}
	return r
}

// serve runs fn inside h's middleware for r and returns the scope.
func (h *testHarness) serve(t *testing.T, r *http.Request, fn func(r *http.Request)) *scope[testSession] {
	t.Helper()
	s, _ := h.do(t, r, func(_ http.ResponseWriter, r *http.Request) { fn(r) })
	return s
}

// do runs fn inside h's middleware for r and returns the scope and response.
func (h *testHarness) do(t *testing.T, r *http.Request, fn func(w http.ResponseWriter, r *http.Request)) (*scope[testSession], *httptest.ResponseRecorder) {
	t.Helper()
	var s *scope[testSession]
	rec := httptest.NewRecorder()
	h.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		s, err = h.manager.scopeFrom(r)
		require.NoError(t, err)
		fn(w, r)
	})).ServeHTTP(rec, r)
	return s, rec
}

func TestManager_Load_RequiresScope(t *testing.T) {
	h := newLoadHarness(t)
	sess, err := h.manager.Load(cookieRequest("anything"))
	assert.Nil(t, sess)
	assert.True(t, errors.Is(err, ErrNoScope))
	assert.False(t, IsNoSession(err))
	assert.Empty(t, h.componentCalls())
}

func TestManager_Load_Success(t *testing.T) {
	h := newLoadHarness(t)
	values := testSession{UserID: 42, Roles: []string{"admin"}}
	credential := h.issue(t, values)

	var first, second *Session[testSession]
	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		var err error
		first, err = h.manager.Load(r)
		require.NoError(t, err)
		second, err = h.manager.Load(r)
		require.NoError(t, err)
	})

	assert.Same(t, first, second, "repeated Load returns the same session")
	assert.Equal(t, values, first.Values())
	assert.False(t, first.IsDirty())
	assert.False(t, first.needsRefresh)
	assert.Equal(t, statePersisted, first.state)
	assert.Equal(t, credential, first.credential)
	assert.True(t, first.meta.ExpiresAt.Equal(loadTestNow.Add(time.Hour)))
	assert.Equal(t, []string{"Read"}, h.transport.Calls())
	assert.Equal(t, []string{"Decode"}, h.encoder.Calls())
	assert.Equal(t, []string{"Load"}, h.store.Calls())
}

func TestManager_Load_KeepsUnsavedChanges(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Set(testSession{UserID: 2}))

		again, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.Equal(t, 2, again.Values().UserID, "no reload over unsaved changes")
	})
}

func TestManager_Load_AfterNew(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		created, err := h.manager.New(r, testSession{UserID: 99})
		require.NoError(t, err)
		loaded, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.Same(t, created, loaded)
	})
	assert.Empty(t, h.componentCalls(), "no credential lookup after New")
}

func TestManager_Load_Unavailable(t *testing.T) {
	tests := map[string]struct {
		setup       func(t *testing.T, h *testHarness) *http.Request
		opts        []ManagerOption
		want        error
		wantCode    string
		wantCleanup bool
		alsoMatches error
	}{
		"no credential": {
			setup: func(t *testing.T, h *testHarness) *http.Request { return cookieRequest() },
			want:  ErrNoSession, wantCode: "SESSION_NONE",
		},
		"ambiguous cookies": {
			setup: func(t *testing.T, h *testHarness) *http.Request {
				return cookieRequest(h.issue(t, testSession{}), h.issue(t, testSession{}))
			},
			want: ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true,
		},
		"malformed credential": {
			setup: func(t *testing.T, h *testHarness) *http.Request { return cookieRequest("not-a-file-store-id") },
			want:  ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true,
		},
		"missing record": {
			setup: func(t *testing.T, h *testHarness) *http.Request {
				credential := h.issue(t, testSession{})
				require.NoError(t, h.store.Store.Delete(t.Context(), credential))
				return cookieRequest(credential)
			},
			want: ErrSessionNotFound, wantCode: "SESSION_NOT_FOUND", wantCleanup: true,
		},
		"stale cookie from another key": {
			setup: func(t *testing.T, h *testHarness) *http.Request {
				oldKey, err := NewHMACEncoder(randomBytes(t, 32))
				require.NoError(t, err)
				return cookieRequest(h.issueWith(t, oldKey, testSession{UserID: 1}, envelopeMeta{
					CreatedAt: loadTestNow.Add(-time.Hour), ExpiresAt: loadTestNow.Add(time.Hour),
				}))
			},
			want: ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true, alsoMatches: ErrInvalidEncoding,
		},
		"tampered record": {
			setup: func(t *testing.T, h *testHarness) *http.Request {
				credential := h.issue(t, testSession{UserID: 1})
				record, err := h.store.Store.Load(t.Context(), credential, testStoreParams())
				require.NoError(t, err)
				record[len(record)/2] ^= 0x01
				_, err = h.store.Store.Update(t.Context(), credential, record, testStoreParams())
				require.NoError(t, err)
				return cookieRequest(credential)
			},
			want: ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true, alsoMatches: ErrInvalidEncoding,
		},
		"oversized record": {
			opts:  []ManagerOption{WithMaxRecordSize(16)},
			setup: func(t *testing.T, h *testHarness) *http.Request { return cookieRequest(h.issue(t, testSession{})) },
			want:  ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true,
		},
		"oversized payload": {
			opts:  []ManagerOption{WithMaxPayloadSize(16)},
			setup: func(t *testing.T, h *testHarness) *http.Request { return cookieRequest(h.issue(t, testSession{})) },
			want:  ErrInvalidSession, wantCode: "SESSION_INVALID", wantCleanup: true,
		},
		"expired": {
			setup: func(t *testing.T, h *testHarness) *http.Request {
				return cookieRequest(h.issueWith(t, h.encoder.Encoder, testSession{UserID: 1}, envelopeMeta{
					CreatedAt: loadTestNow.Add(-2 * time.Hour), ExpiresAt: loadTestNow,
				}))
			},
			want: ErrSessionExpired, wantCode: "SESSION_EXPIRED", wantCleanup: true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t, tc.opts...)
			r := tc.setup(t, h)
			presented := r.Header.Get("Cookie")

			s := h.serve(t, r, func(r *http.Request) {
				sess, err := h.manager.Load(r)
				assert.Nil(t, sess)
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.want)
				if tc.alsoMatches != nil {
					assert.ErrorIs(t, err, tc.alsoMatches)
				}
				assert.True(t, IsNoSession(err))
				assert.Equal(t, tc.wantCode, errors.TypeCode(err))
				assert.Equal(t, http.StatusUnauthorized, errors.HTTPCode(err))
				for _, cookie := range strings.Split(presented, "; ") {
					if value, ok := strings.CutPrefix(cookie, "session="); ok && len(value) > 8 {
						assert.NotContains(t, err.Error(), value, "credential must not appear in the error")
					}
				}

				calls := len(h.componentCalls())
				again, againErr := h.manager.Load(r)
				assert.Nil(t, again)
				assert.Same(t, err, againErr, "outcome is cached")
				assert.Len(t, h.componentCalls(), calls, "no second lookup")
			})

			assert.Equal(t, tc.wantCleanup, s.pendingCleanup)
			assert.Nil(t, s.active, "no session constructed")
		})
	}
}

// Operational failures are returned unchanged, not cached, and retried.
func TestManager_Load_OperationalFailures(t *testing.T) {
	operational := errors.ErrUnavailable.Msg("backend down")
	tests := map[string]func(h *testHarness){
		"transport": func(h *testHarness) { h.transport.FailWith("Read", operational) },
		"store":     func(h *testHarness) { h.store.FailWith("Load", operational) },
		"encoder":   func(h *testHarness) { h.encoder.FailWith("Decode", operational) },
	}
	for name, fail := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			credential := h.issue(t, testSession{UserID: 5})
			fail(h)

			s := h.serve(t, cookieRequest(credential), func(r *http.Request) {
				sess, err := h.manager.Load(r)
				assert.Nil(t, sess)
				assert.ErrorIs(t, err, operational)
				assert.False(t, IsNoSession(err))

				h.transport.FailWith("Read", nil)
				h.store.FailWith("Load", nil)
				h.encoder.FailWith("Decode", nil)

				sess, err = h.manager.Load(r)
				require.NoError(t, err, "operational failures are retried")
				assert.Equal(t, 5, sess.Values().UserID)
			})
			assert.False(t, s.pendingCleanup)
			assert.Nil(t, s.loadErr)
		})
	}
}

func TestManager_Load_ValuesMismatchIsOperational(t *testing.T) {
	h := newLoadHarness(t)
	payload := []byte(`{"v":1,"c":1749990000,"e":1750010000,"d":{"user_id":"not a number"}}`)
	record, err := h.encoder.Encoder.Encode(payload)
	require.NoError(t, err)
	credential, err := h.store.Store.Create(t.Context(), record, testStoreParams())
	require.NoError(t, err)

	s := h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.Load(r)
		assert.Nil(t, sess)
		require.Error(t, err)
		assert.False(t, IsNoSession(err))
		assert.Equal(t, http.StatusInternalServerError, errors.HTTPCode(err))

		_, _ = h.manager.Load(r)
	})
	assert.Nil(t, s.loadErr, "not cached")
	assert.False(t, s.pendingCleanup)
	assert.Equal(t, []string{"Load", "Load"}, h.store.Calls(), "retried")
}

func TestManager_Load_PermissionErrorIsOperational(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions are not enforced here")
	}

	h := newLoadHarness(t)
	credential := h.issue(t, testSession{})
	dir := h.store.Store.(*FileStore).dir
	path := filepath.Join(dir, "session_"+credential)
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.Load(r)
		assert.Nil(t, sess)
		require.Error(t, err)
		assert.False(t, IsNoSession(err))
		assert.Equal(t, http.StatusInternalServerError, errors.HTTPCode(err))
		assert.NotContains(t, err.Error(), credential)
	})
}

func TestManager_Load_RotatedKeyNeedsRefresh(t *testing.T) {
	newKey, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	oldKey, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	rotating, err := NewRotatingEncoder(newKey, oldKey)
	require.NoError(t, err)

	h := newLoadHarness(t)
	h.manager.encoder = rotating
	meta := envelopeMeta{CreatedAt: loadTestNow.Add(-time.Hour), ExpiresAt: loadTestNow.Add(time.Hour)}

	tests := map[string]struct {
		producer    Encoder
		wantRefresh bool
	}{
		"current key":  {producer: newKey, wantRefresh: false},
		"previous key": {producer: oldKey, wantRefresh: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			credential := h.issueWith(t, tc.producer, testSession{UserID: 3}, meta)
			h.serve(t, cookieRequest(credential), func(r *http.Request) {
				sess, err := h.manager.Load(r)
				require.NoError(t, err)
				assert.Equal(t, 3, sess.Values().UserID)
				assert.Equal(t, tc.wantRefresh, sess.needsRefresh)
				assert.False(t, sess.IsDirty(), "refresh is not value dirtiness")
			})
		})
	}
}

func TestManager_LoadOrNew_RequiresScope(t *testing.T) {
	h := newLoadHarness(t)
	sess, err := h.manager.LoadOrNew(cookieRequest("anything"))
	assert.Nil(t, sess)
	assert.True(t, errors.Is(err, ErrNoScope))
	assert.False(t, IsNoSession(err))
}

func TestManager_LoadOrNew_ReturnsLoadedSession(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 7})

	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.LoadOrNew(r)
		require.NoError(t, err)
		assert.False(t, sess.IsNew())
		assert.Equal(t, 7, sess.Values().UserID)

		loaded, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.Same(t, sess, loaded)
	})
}

func TestManager_LoadOrNew_CreatesWhenNoSession(t *testing.T) {
	tests := map[string]func(t *testing.T, h *testHarness) *http.Request{
		"no credential": func(t *testing.T, h *testHarness) *http.Request { return cookieRequest() },
		"invalid credential": func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest("not-a-valid-credential")
		},
		"expired": func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest(h.issueWith(t, h.encoder.Encoder, testSession{UserID: 1}, envelopeMeta{
				CreatedAt: loadTestNow.Add(-2 * time.Hour),
				ExpiresAt: loadTestNow.Add(-time.Hour),
			}))
		},
	}
	for name, setup := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			r := setup(t, h)

			_, rec := h.do(t, r, func(w http.ResponseWriter, r *http.Request) {
				sess, err := h.manager.LoadOrNew(r)
				require.NoError(t, err)
				assert.True(t, sess.IsNew())
				assert.Equal(t, testSession{}, sess.Values())

				require.NoError(t, sess.Set(testSession{UserID: 9}))
				require.NoError(t, sess.Save(w))
				assert.False(t, sess.IsNew())
			})

			cookies := rec.Result().Cookies()
			require.Len(t, cookies, 1, "saving the new session issues one credential")
			assert.NotEmpty(t, cookies[0].Value)
		})
	}
}

func TestManager_LoadOrNew_UntouchedIsNotPersisted(t *testing.T) {
	h := newLoadHarness(t)

	_, rec := h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.LoadOrNew(r)
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
		assert.True(t, sess.IsNew(), "nothing was persisted")
		assert.True(t, sess.IsCommitted())
	})

	assert.Empty(t, rec.Result().Cookies())
	assert.Empty(t, h.store.Calls())
}

func TestManager_LoadOrNew_AfterDelete(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 3})

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, h.manager.Delete(w, r))

		sess, err := h.manager.LoadOrNew(r)
		require.NoError(t, err)
		assert.True(t, sess.IsNew())
		assert.Equal(t, testSession{}, sess.Values())
	})
}

func TestManager_LoadOrNew_OperationalFailure(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 5})
	operational := errors.ErrUnavailable.Msg("backend down")
	h.store.FailWith("Load", operational)

	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.LoadOrNew(r)
		assert.Nil(t, sess)
		assert.ErrorIs(t, err, operational)
		assert.False(t, IsNoSession(err))
	})
}
