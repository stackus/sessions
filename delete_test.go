package sessions

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertCleared asserts that rec expires the session cookie.
func assertCleared(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie, "session cookie cleared")
	assert.Empty(t, cookie.Value)
	assert.Less(t, cookie.MaxAge, 0)
}

func assertDeleted(t *testing.T, sess *Session[testSession]) {
	t.Helper()
	assert.Equal(t, stateDeleted, sess.state)
	assert.ErrorIs(t, sess.Set(testSession{}), ErrSessionDeleted)
	assert.ErrorIs(t, sess.Update(func(*testSession) {}), ErrSessionDeleted)
	assert.ErrorIs(t, sess.Save(httptest.NewRecorder()), ErrSessionDeleted)
	assert.ErrorIs(t, sess.Delete(httptest.NewRecorder()), ErrSessionDeleted)
}

func TestDelete_RequiresScope(t *testing.T) {
	h := newLoadHarness(t)
	err := h.manager.Delete(httptest.NewRecorder(), cookieRequest("anything"))
	assert.ErrorIs(t, err, ErrNoScope)
	assert.Empty(t, h.trace.Calls())
}

func TestDelete_LoadedSession(t *testing.T) {
	for name, viaSession := range map[string]bool{"manager": false, "session": true} {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			credential := h.issue(t, testSession{UserID: 1})

			var sess *Session[testSession]
			_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
				var err error
				sess, err = h.manager.Load(r)
				require.NoError(t, err)
				if viaSession {
					require.NoError(t, sess.Delete(w))
				} else {
					require.NoError(t, h.manager.Delete(w, r))
				}

				loaded, err := h.manager.Load(r)
				assert.Nil(t, loaded)
				assert.ErrorIs(t, err, ErrSessionDeleted)
				assert.True(t, IsNoSession(err))
			})

			assert.Equal(t,
				[]string{"transport.Read", "store.Load", "encoder.Decode", "store.Delete", "transport.Clear"},
				h.trace.Calls())
			assertDeleted(t, sess)
			assertCleared(t, rec)
			_, err := h.loadIn(t, credential)
			assert.ErrorIs(t, err, ErrSessionNotFound, "record deleted")
		})
	}
}

func TestDelete_WithoutLoad(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, h.manager.Delete(w, r))
		_, err := h.manager.Load(r)
		assert.ErrorIs(t, err, ErrSessionDeleted)
	})

	assert.Equal(t, []string{"transport.Read", "store.Delete", "transport.Clear"}, h.trace.Calls(),
		"no Store.Load and no decode")
	assertCleared(t, rec)
	_, err := h.loadIn(t, credential)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestDelete_UndecodableCredentials(t *testing.T) {
	tests := map[string]struct {
		cookies   []string
		wantStore []string
	}{
		"garbage credential":  {cookies: []string{"garbage"}, wantStore: []string{"Delete"}},
		"ambiguous cookies":   {cookies: []string{"one", "two"}, wantStore: nil},
		"no credential":       {cookies: nil, wantStore: nil},
		"valid id, no record": {cookies: []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, wantStore: []string{"Delete"}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			dir := h.store.Store.(*FileStore).dir
			before := dirSnapshot(t, dir)

			_, rec := h.do(t, cookieRequest(tc.cookies...), func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, h.manager.Delete(w, r))
			})

			assert.Equal(t, tc.wantStore, h.store.Calls())
			assert.Empty(t, h.encoder.Calls(), "never decodes")
			assert.Equal(t, []string{"Read", "Clear"}, h.transport.Calls())
			assertCleared(t, rec)
			assert.Equal(t, before, dirSnapshot(t, dir), "no file touched")
		})
	}
}

func TestDelete_AfterRejectedLoad(t *testing.T) {
	h := newLoadHarness(t)
	s, rec := h.do(t, cookieRequest("garbage"), func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		require.ErrorIs(t, err, ErrInvalidSession)
		require.NoError(t, h.manager.Delete(w, r))
	})

	assert.Equal(t, []string{"Read", "Clear"}, h.transport.Calls(), "credential not read twice")
	assert.Equal(t, []string{"Load", "Delete"}, h.store.Calls())
	assert.Nil(t, s.active, "no session constructed")
	assert.False(t, s.pendingCleanup)
	assertCleared(t, rec)
}

func TestDelete_AfterSaveIsCommitted(t *testing.T) {
	h := newLoadHarness(t)
	h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r, testSession{UserID: 1})
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))

		assert.ErrorIs(t, h.manager.Delete(w, r), ErrSessionCommitted)
		assert.ErrorIs(t, sess.Delete(w), ErrSessionCommitted)
	})
	assert.NotContains(t, h.trace.Calls(), "transport.Clear")
}

func TestDelete_Repeated(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, h.manager.Delete(w, r))
		calls := len(h.trace.Calls())

		require.NoError(t, h.manager.Delete(w, r))
		assert.Len(t, h.trace.Calls(), calls, "no extra component calls")

		fresh, err := h.manager.New(r)
		require.NoError(t, err)
		require.NoError(t, h.manager.Delete(w, r))
		assertDeleted(t, fresh)
		assert.Len(t, h.trace.Calls(), calls)
	})
}

func TestDelete_Failures(t *testing.T) {
	operational := errors.ErrUnavailable.Msg("backend down")
	tests := map[string]struct {
		recorder   func(h *testHarness) *callRecorder
		method     string
		wantClear  bool
		recordKept bool
	}{
		"store delete":    {recorder: func(h *testHarness) *callRecorder { return &h.store.callRecorder }, method: "Delete", recordKept: true},
		"transport read":  {recorder: func(h *testHarness) *callRecorder { return &h.transport.callRecorder }, method: "Read", recordKept: true},
		"transport clear": {recorder: func(h *testHarness) *callRecorder { return &h.transport.callRecorder }, method: "Clear", wantClear: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			credential := h.issue(t, testSession{UserID: 1})
			tc.recorder(h).FailWith(tc.method, operational)

			s, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
				err := h.manager.Delete(w, r)
				require.Error(t, err)
				assert.ErrorIs(t, err, operational)
				assert.Equal(t, http.StatusServiceUnavailable, errors.HTTPCode(err))
				assert.False(t, IsNoSession(err))
			})
			tc.recorder(h).FailWith(tc.method, nil)

			assert.False(t, s.deleted, "not marked deleted")
			assert.Nil(t, s.loadErr)
			assert.Equal(t, tc.wantClear, slices.Contains(h.transport.Calls(), "Clear"))
			assert.Nil(t, responseCookie(t, rec), "client credential not reported as cleared")
			if tc.recordKept {
				_, err := h.loadIn(t, credential)
				assert.NoError(t, err, "record kept")
			}
		})
	}
}

func TestDelete_ThenNewSession(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	var fresh *Session[testSession]
	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		loaded, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, loaded.Delete(w))

		fresh, err = h.manager.New(r, testSession{UserID: 2})
		require.NoError(t, err)
		again, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.Same(t, fresh, again, "Load returns the new session")

		require.NoError(t, fresh.Save(w))
		assertDeleted(t, loaded)
	})

	assert.Equal(t, 1, countOf(h.store.Calls(), "Delete"), "the new session's save deletes nothing more")
	cookies := setCookies(t, rec)
	require.Len(t, cookies, 2, "clear, then the new credential")
	assert.Less(t, cookies[0].MaxAge, 0)
	assert.Equal(t, fresh.credential, cookies[1].Value)

	values, err := h.loadIn(t, fresh.credential)
	require.NoError(t, err)
	assert.Equal(t, 2, values.UserID)
	_, err = h.loadIn(t, credential)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func countOf(list []string, v string) int {
	n := 0
	for _, item := range list {
		if item == v {
			n++
		}
	}
	return n
}

func TestDelete_CoversReplacedAndNewCredentials(t *testing.T) {
	h := newLoadHarness(t)
	oldCredential := h.issue(t, testSession{UserID: 1})

	var loaded, replacement *Session[testSession]
	h.do(t, cookieRequest(oldCredential), func(w http.ResponseWriter, r *http.Request) {
		var err error
		loaded, err = h.manager.Load(r)
		require.NoError(t, err)
		replacement, err = h.manager.New(r, testSession{UserID: 2})
		require.NoError(t, err)

		// The replacement is unsaved, so the presented record is the only one
		// to delete; both sessions end up deleted.
		require.NoError(t, h.manager.Delete(w, r))
	})
	assertDeleted(t, loaded)
	assertDeleted(t, replacement)
	_, err := h.loadIn(t, oldCredential)
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestDelete_DeletesEveryKnownCredential(t *testing.T) {
	h := newLoadHarness(t)
	presented := h.issue(t, testSession{UserID: 1})
	issued := h.issue(t, testSession{UserID: 2})

	s, _ := h.do(t, cookieRequest(presented), func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		require.NoError(t, err)
		s, _ := h.manager.scopeFrom(r)
		s.issued = append(s.issued, issued, presented) // duplicates are deleted once
		assert.Equal(t, []string{presented, issued}, s.knownCredentials())

		require.NoError(t, h.manager.Delete(w, r))
	})

	assert.Equal(t, 2, countOf(h.store.Calls(), "Delete"))
	assert.Empty(t, s.knownCredentials())
	for _, credential := range []string{presented, issued} {
		_, err := h.loadIn(t, credential)
		assert.ErrorIs(t, err, ErrSessionNotFound)
	}
}
