package sessions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inScope runs fn inside h's middleware and returns the scope it ran in.
func inScope(t *testing.T, h *testHarness, fn func(r *http.Request)) *scope[testSession] {
	t.Helper()
	return h.serve(t, httptest.NewRequest(http.MethodGet, "/", nil), fn)
}

func TestManager_New(t *testing.T) {
	h := newTestHarness(t)

	inScope(t, h, func(r *http.Request) {
		sess, err := h.manager.New(r)
		require.NoError(t, err)
		assert.Equal(t, testSession{}, sess.Values())
		assert.False(t, sess.IsDirty(), "untouched")
		assert.Equal(t, stateNew, sess.state)

		initial := testSession{UserID: 42, Roles: []string{"admin"}}
		sess, err = h.manager.New(r, initial)
		require.NoError(t, err)
		assert.Equal(t, initial, sess.Values())
		assert.True(t, sess.IsDirty(), "an initial value makes the session dirty")

		sess, err = h.manager.New(r, testSession{UserID: 1}, testSession{UserID: 2})
		require.Error(t, err)
		assert.Nil(t, sess)
		assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
	})

	assert.Empty(t, h.componentCalls(), "New does no transport, encoder, or store work")
}

func TestManager_New_RequiresScope(t *testing.T) {
	h := newTestHarness(t)
	sess, err := h.manager.New(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.Nil(t, sess)
	assert.True(t, errors.Is(err, ErrNoScope))
}

func TestManager_New_IsActiveSession(t *testing.T) {
	h := newTestHarness(t)
	var sess *Session[testSession]
	s := inScope(t, h, func(r *http.Request) {
		var err error
		sess, err = h.manager.New(r)
		require.NoError(t, err)
	})
	assert.Same(t, sess, s.active)
	assert.Same(t, s, sess.scope)
	assert.Nil(t, s.replaced)
}

func TestManager_New_ReplacesLoadedSession(t *testing.T) {
	h := newTestHarness(t)
	var loaded, first, second *Session[testSession]
	s := inScope(t, h, func(r *http.Request) {
		s, _ := h.manager.scopeFrom(r)
		loaded = &Session[testSession]{state: statePersisted, scope: s}
		s.active = loaded

		var err error
		first, err = h.manager.New(r)
		require.NoError(t, err)
		second, err = h.manager.New(r, testSession{UserID: 7})
		require.NoError(t, err)
	})

	assert.Same(t, second, s.active)
	assert.Same(t, loaded, s.replaced, "the loaded record stays the one to delete")
	for name, sess := range map[string]*Session[testSession]{"loaded": loaded, "superseded new": first} {
		assert.Equal(t, stateReplaced, sess.state, name)
		assert.ErrorIs(t, sess.Set(testSession{}), ErrSessionReplaced, name)
		assert.ErrorIs(t, sess.Update(func(*testSession) {}), ErrSessionReplaced, name)
	}
	assert.Empty(t, h.componentCalls(), "replacement reads no credential")
}

func TestSession_SetAndUpdate(t *testing.T) {
	sess := &Session[testSession]{state: statePersisted}

	require.NoError(t, sess.Set(testSession{}))
	assert.True(t, sess.IsDirty(), "setting the zero value is an intentional change")

	sess.dirty = false
	require.NoError(t, sess.Set(sess.Values()))
	assert.True(t, sess.IsDirty(), "setting equal values still marks dirty")

	sess.dirty = false
	require.NoError(t, sess.Update(func(v *testSession) { v.UserID = 9 }))
	assert.True(t, sess.IsDirty())
	assert.Equal(t, 9, sess.Values().UserID)
}

func TestSession_UpdatePanicLeavesDirty(t *testing.T) {
	sess := &Session[testSession]{state: statePersisted}
	assert.Panics(t, func() {
		_ = sess.Update(func(v *testSession) {
			v.UserID = 5
			panic("callback failed")
		})
	})
	assert.True(t, sess.IsDirty())
	assert.Equal(t, 5, sess.Values().UserID, "no rollback")
}

func TestSession_ValuesIsShallowCopy(t *testing.T) {
	sess := &Session[testSession]{values: testSession{UserID: 1, Roles: []string{"user"}}}

	v := sess.Values()
	v.UserID = 2
	assert.Equal(t, 1, sess.Values().UserID, "struct fields are copied")

	v.Roles[0] = "admin"
	assert.Equal(t, "admin", sess.Values().Roles[0], "reference fields alias session memory")
	assert.False(t, sess.IsDirty(), "aliased changes are not tracked")
}

func TestSession_WritableStatePrecedence(t *testing.T) {
	tests := map[string]struct {
		state     sessionState
		committed bool
		want      error
	}{
		"new":                    {state: stateNew},
		"persisted":              {state: statePersisted},
		"committed":              {state: statePersisted, committed: true, want: ErrSessionCommitted},
		"replaced":               {state: stateReplaced, want: ErrSessionReplaced},
		"replaced and committed": {state: stateReplaced, committed: true, want: ErrSessionReplaced},
		"deleted":                {state: stateDeleted, want: ErrSessionDeleted},
		"deleted and committed":  {state: stateDeleted, committed: true, want: ErrSessionDeleted},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sess := &Session[testSession]{state: tc.state, committed: tc.committed, values: testSession{UserID: 1}}

			setErr := sess.Set(testSession{UserID: 2})
			called := false
			updateErr := sess.Update(func(*testSession) { called = true })

			if tc.want == nil {
				assert.NoError(t, setErr)
				assert.NoError(t, updateErr)
				assert.True(t, called)
				return
			}
			assert.ErrorIs(t, setErr, tc.want)
			assert.ErrorIs(t, updateErr, tc.want)
			assert.False(t, called, "callback not run")
			assert.False(t, sess.IsDirty())
			assert.Equal(t, 1, sess.Values().UserID, "values unchanged")
		})
	}
}

func TestSession_StateAccessors(t *testing.T) {
	h := newTestHarness(t)

	h.do(t, httptest.NewRequest(http.MethodGet, "/", nil), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r)
		require.NoError(t, err)
		assert.True(t, sess.IsNew())
		assert.False(t, sess.IsDirty())
		assert.False(t, sess.IsCommitted())

		require.NoError(t, sess.Set(testSession{UserID: 1}))
		assert.True(t, sess.IsDirty())

		h.store.FailWith("Create", errors.ErrUnavailable.Msg("store down"))
		require.Error(t, sess.Save(w))
		assert.True(t, sess.IsNew(), "a failed Save persists nothing")
		assert.True(t, sess.IsDirty(), "a failed Save keeps the changes")
		assert.False(t, sess.IsCommitted(), "a failed Save does not commit")

		h.store.FailWith("Create", nil)
		require.NoError(t, sess.Save(w))
		assert.False(t, sess.IsNew())
		assert.False(t, sess.IsDirty())
		assert.True(t, sess.IsCommitted())
	})
}
