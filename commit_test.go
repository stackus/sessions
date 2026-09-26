package sessions

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// responseCookie returns the session cookie set on rec, or nil.
func responseCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	var found *http.Cookie
	for _, c := range setCookies(t, rec) {
		if c.Name == "session" {
			require.Nil(t, found, "more than one session cookie set")
			found = c
		}
	}
	return found
}

// loadIn loads the session presented by credential in a fresh request.
func (h *testHarness) loadIn(t *testing.T, credential string) (testSession, error) {
	t.Helper()
	var values testSession
	var loadErr error
	h.serve(t, cookieRequest(credential), func(r *http.Request) {
		sess, err := h.manager.Load(r)
		loadErr = err
		if err == nil {
			values = sess.Values()
		}
	})
	return values, loadErr
}

func assertCommitted(t *testing.T, sess *Session[testSession]) {
	t.Helper()
	assert.True(t, sess.committed)
	assert.ErrorIs(t, sess.Set(testSession{}), ErrSessionCommitted)
	assert.ErrorIs(t, sess.Update(func(*testSession) {}), ErrSessionCommitted)
}

func TestSave_NewUntouched(t *testing.T) {
	h := newLoadHarness(t)
	_, rec := h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r)
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
		assertCommitted(t, sess)
		assert.Equal(t, stateNew, sess.state, "not persisted")
		assert.NoError(t, sess.Save(w), "repeated Save is a no-op")
	})
	assert.Empty(t, h.trace.Calls(), "no persistence")
	assert.Nil(t, responseCookie(t, rec))
}

func TestSave_NewDirty(t *testing.T) {
	h := newLoadHarness(t, WithLifetime(time.Hour))
	var saved *Session[testSession]
	s, rec := h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r, testSession{UserID: 42})
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
		assert.NoError(t, sess.Save(w), "repeated Save is a no-op")
		saved = sess
	})

	assert.Equal(t, []string{"encoder.Encode", "store.Create", "transport.Write"}, h.trace.Calls())
	assertCommitted(t, saved)
	assert.Equal(t, statePersisted, saved.state)
	assert.False(t, saved.IsDirty())
	assert.True(t, saved.meta.CreatedAt.Equal(loadTestNow))
	assert.True(t, saved.meta.ExpiresAt.Equal(loadTestNow.Add(time.Hour)), "WithLifetime honored")
	assert.Equal(t, []string{saved.credential}, s.issued)

	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie)
	assert.Equal(t, saved.credential, cookie.Value)

	values, err := h.loadIn(t, cookie.Value)
	require.NoError(t, err)
	assert.Equal(t, 42, values.UserID)
}

func TestSave_LoadedClean(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})

	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
		assertCommitted(t, sess)
	})
	assert.Equal(t, []string{"transport.Read", "store.Load", "encoder.Decode"}, h.trace.Calls())
	assert.Nil(t, responseCookie(t, rec))
}

func TestSave_LoadedDirty_StableCredential(t *testing.T) {
	h := newLoadHarness(t)
	meta := envelopeMeta{CreatedAt: loadTestNow.Add(-time.Hour), ExpiresAt: loadTestNow.Add(time.Hour)}
	credential := h.issueWith(t, h.encoder.Encoder, testSession{UserID: 1}, meta)

	var saved *Session[testSession]
	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Update(func(v *testSession) { v.UserID = 2 }))
		require.NoError(t, sess.Save(w))
		saved = sess
	})

	assert.Equal(t, []string{"Load", "Update"}, h.store.Calls())
	assert.Equal(t, []string{"Read"}, h.transport.Calls(), "stable FileStore ID is not reissued")
	assert.Nil(t, responseCookie(t, rec))
	assertCommitted(t, saved)
	assert.False(t, saved.IsDirty())
	assert.Equal(t, credential, saved.credential)
	assert.True(t, saved.meta.ExpiresAt.Equal(meta.ExpiresAt), "absolute expiry preserved")

	values, err := h.loadIn(t, credential)
	require.NoError(t, err)
	assert.Equal(t, 2, values.UserID)
}

func TestSave_LoadedDirty_ChangedCredential(t *testing.T) {
	h := newTestHarnessWithStore(t, NewCookieStore())
	h.manager.now = func() time.Time { return loadTestNow }
	credential := h.issue(t, testSession{UserID: 1})

	var saved *Session[testSession]
	s, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Set(testSession{UserID: 2}))
		require.NoError(t, sess.Save(w))
		saved = sess
	})

	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie, "CookieStore credential changes on update")
	assert.NotEqual(t, credential, cookie.Value)
	assert.Equal(t, saved.credential, cookie.Value)
	assert.Equal(t, []string{cookie.Value}, s.issued)

	values, err := h.loadIn(t, cookie.Value)
	require.NoError(t, err)
	assert.Equal(t, 2, values.UserID)
}

func TestSave_ClearingValuesIsPersisted(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1, Roles: []string{"admin"}})

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Set(testSession{}))
		require.NoError(t, sess.Save(w))
	})

	values, err := h.loadIn(t, credential)
	require.NoError(t, err)
	assert.Equal(t, testSession{}, values)
}

func TestSave_FailuresLeaveSessionUncommitted(t *testing.T) {
	operational := errors.ErrUnavailable.Msg("backend down")
	tests := map[string]struct {
		loaded bool
		fail   func(h *testHarness)
		clear  func(h *testHarness)
	}{
		"create fails": {
			fail:  func(h *testHarness) { h.store.FailWith("Create", operational) },
			clear: func(h *testHarness) { h.store.FailWith("Create", nil) },
		},
		"encode fails": {
			fail:  func(h *testHarness) { h.encoder.FailWith("Encode", operational) },
			clear: func(h *testHarness) { h.encoder.FailWith("Encode", nil) },
		},
		"issue fails after create": {
			fail:  func(h *testHarness) { h.transport.FailWith("Write", operational) },
			clear: func(h *testHarness) { h.transport.FailWith("Write", nil) },
		},
		"update fails": {
			loaded: true,
			fail:   func(h *testHarness) { h.store.FailWith("Update", operational) },
			clear:  func(h *testHarness) { h.store.FailWith("Update", nil) },
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			h := newLoadHarness(t)
			r := cookieRequest()
			if tc.loaded {
				r = cookieRequest(h.issue(t, testSession{UserID: 1}))
			}

			_, rec := h.do(t, r, func(w http.ResponseWriter, r *http.Request) {
				var sess *Session[testSession]
				var err error
				if tc.loaded {
					sess, err = h.manager.Load(r)
					require.NoError(t, err)
					require.NoError(t, sess.Set(testSession{UserID: 2}))
				} else {
					sess, err = h.manager.New(r, testSession{UserID: 2})
					require.NoError(t, err)
				}

				tc.fail(h)
				err = sess.Save(w)
				require.Error(t, err)
				assert.ErrorIs(t, err, operational)
				assert.Equal(t, http.StatusServiceUnavailable, errors.HTTPCode(err), "classification kept")
				assert.False(t, IsNoSession(err))
				assert.False(t, sess.committed)
				assert.True(t, sess.IsDirty())
				assert.NoError(t, sess.Update(func(v *testSession) { v.UserID = 3 }), "still writable")

				tc.clear(h)
				require.NoError(t, sess.Save(w), "retry succeeds")
				assert.True(t, sess.committed)
			})

			if !tc.loaded {
				cookies := responseCookie(t, rec)
				require.NotNil(t, cookies)
				values, err := h.loadIn(t, cookies.Value)
				require.NoError(t, err)
				assert.Equal(t, 3, values.UserID)
			}
		})
	}
}

func TestSave_IssueFailureRollsBackCreatedRecord(t *testing.T) {
	h := newLoadHarness(t)
	h.transport.FailWith("Write", errors.ErrInternal.Msg("headers already sent"))
	fileStore := h.store.Store.(*FileStore)

	h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r, testSession{UserID: 1})
		require.NoError(t, err)
		require.Error(t, sess.Save(w))
	})
	assert.Equal(t, []string{"store.Create", "transport.Write", "store.Delete"}, filterTrace(h.trace.Calls(), "store.", "transport."))
	assert.Equal(t, []string{"."}, dirSnapshot(t, fileStore.dir), "no orphan record")
}

// filterTrace keeps the trace entries with one of the given prefixes.
func filterTrace(calls []string, prefixes ...string) []string {
	var out []string
	for _, c := range calls {
		for _, p := range prefixes {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func TestSave_ChangedCredentialRetriedAfterIssueFailure(t *testing.T) {
	// A store that changes the credential on update: if issuing it fails, a
	// retry must still deliver it.
	h := newTestHarnessWithStore(t, NewCookieStore())
	h.manager.now = func() time.Time { return loadTestNow }
	credential := h.issue(t, testSession{UserID: 1})

	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Set(testSession{UserID: 2}))

		h.transport.FailWith("Write", errors.ErrInternal.Msg("write failed"))
		require.Error(t, sess.Save(w))
		assert.True(t, sess.unsent)

		h.transport.FailWith("Write", nil)
		require.NoError(t, sess.Save(w))
		assert.False(t, sess.unsent)
	})
	require.NotNil(t, responseCookie(t, rec))
}

func TestSave_Replacement(t *testing.T) {
	h := newLoadHarness(t)
	oldCredential := h.issue(t, testSession{UserID: 1})

	var loaded, replacement *Session[testSession]
	s, rec := h.do(t, cookieRequest(oldCredential), func(w http.ResponseWriter, r *http.Request) {
		var err error
		loaded, err = h.manager.Load(r)
		require.NoError(t, err)
		replacement, err = h.manager.New(r, testSession{UserID: 2})
		require.NoError(t, err)
		require.NoError(t, replacement.Save(w))

		assert.ErrorIs(t, loaded.Save(w), ErrSessionReplaced)
	})

	assert.Equal(t,
		[]string{"transport.Read", "store.Load", "store.Create", "transport.Write", "store.Delete"},
		filterTrace(h.trace.Calls(), "store.", "transport."),
		"create, then issue, then delete the old record")
	assert.NotEqual(t, oldCredential, replacement.credential, "old ID is never reused")
	assert.Nil(t, s.replaced)

	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie)
	assert.Equal(t, replacement.credential, cookie.Value)

	_, err := h.loadIn(t, oldCredential)
	assert.ErrorIs(t, err, ErrSessionNotFound, "old record deleted")
	values, err := h.loadIn(t, cookie.Value)
	require.NoError(t, err)
	assert.Equal(t, 2, values.UserID)
}

func TestSave_ReplacementDeleteFailure(t *testing.T) {
	h := newLoadHarness(t)
	oldCredential := h.issue(t, testSession{UserID: 1})
	deleteErr := errors.ErrUnavailable.Msg("store down")

	_, rec := h.do(t, cookieRequest(oldCredential), func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		require.NoError(t, err)
		replacement, err := h.manager.New(r, testSession{UserID: 2})
		require.NoError(t, err)

		h.store.FailWith("Delete", deleteErr)
		err = replacement.Save(w)
		assert.ErrorIs(t, err, deleteErr)
		assertCommitted(t, replacement)
		assert.NoError(t, replacement.Save(w), "already committed")
	})

	require.NotNil(t, responseCookie(t, rec), "new credential issued")
	_, err := h.loadIn(t, oldCredential)
	assert.NoError(t, err, "old record left behind until it expires")
}

func TestSave_UntouchedReplacementKeepsOldSession(t *testing.T) {
	h := newLoadHarness(t)
	oldCredential := h.issue(t, testSession{UserID: 1})

	_, rec := h.do(t, cookieRequest(oldCredential), func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		require.NoError(t, err)
		replacement, err := h.manager.New(r)
		require.NoError(t, err)
		require.NoError(t, replacement.Save(w))
	})

	assert.Equal(t, []string{"Load"}, h.store.Calls())
	assert.Nil(t, responseCookie(t, rec))
	values, err := h.loadIn(t, oldCredential)
	require.NoError(t, err)
	assert.Equal(t, 1, values.UserID)
}

func TestSave_ClearsPendingCleanup(t *testing.T) {
	h := newLoadHarness(t)
	s, rec := h.do(t, cookieRequest("garbage"), func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		require.ErrorIs(t, err, ErrInvalidSession)

		sess, err := h.manager.New(r, testSession{UserID: 1})
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
	})
	assert.False(t, s.pendingCleanup, "the new credential replaces the rejected one")
	require.NotNil(t, responseCookie(t, rec))
}

func TestSave_RefreshAfterKeyRotation(t *testing.T) {
	newKey, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	oldKey, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	rotating, err := NewRotatingEncoder(newKey, oldKey)
	require.NoError(t, err)

	h := newLoadHarness(t)
	h.manager.encoder = rotating
	meta := envelopeMeta{CreatedAt: loadTestNow.Add(-time.Hour), ExpiresAt: loadTestNow.Add(time.Hour)}
	credential := h.issueWith(t, oldKey, testSession{UserID: 3}, meta)

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.True(t, sess.needsRefresh)
		require.NoError(t, sess.Save(w))
		assert.False(t, sess.IsDirty())
		assert.False(t, sess.needsRefresh)
	})
	assert.Equal(t, []string{"Load", "Update"}, h.store.Calls(), "record rewritten without value changes")

	record, err := h.store.Store.Load(t.Context(), credential, testStoreParams())
	require.NoError(t, err)
	payload, err := newKey.Decode(record)
	require.NoError(t, err, "rewritten with the current key")
	values, got, err := unmarshalEnvelope[testSession](payload, loadTestNow, defaultMaxPayloadSize)
	require.NoError(t, err)
	assert.Equal(t, 3, values.UserID)
	assert.True(t, got.ExpiresAt.Equal(meta.ExpiresAt))
}

func TestSave_RecordTooLargeIsOperational(t *testing.T) {
	h := newLoadHarness(t, WithMaxRecordSize(32))
	h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r, testSession{UserID: 1, Roles: []string{"a", "b", "c"}})
		require.NoError(t, err)
		err = sess.Save(w)
		require.Error(t, err)
		assert.False(t, IsNoSession(err))
		assert.Equal(t, "INTERNAL", errors.TypeCode(err))
		assert.False(t, sess.committed)
	})
	assert.Empty(t, h.store.Calls(), "nothing stored")
}

func TestSave_DeletedOrReplaced(t *testing.T) {
	tests := map[string]struct {
		state sessionState
		want  error
	}{
		"deleted":  {state: stateDeleted, want: ErrSessionDeleted},
		"replaced": {state: stateReplaced, want: ErrSessionReplaced},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			sess := &Session[testSession]{state: tc.state, dirty: true}
			assert.ErrorIs(t, sess.Save(httptest.NewRecorder()), tc.want)
		})
	}
}

func TestSave_EndToEnd(t *testing.T) {
	hmacEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)
	aesEnc, err := NewAESGCMEncoder(randomBytes(t, 32))
	require.NoError(t, err)

	configs := map[string]func(t *testing.T) (Encoder, Store){
		"A: base64 + file store": func(t *testing.T) (Encoder, Store) {
			store, err := NewFileStore(t.TempDir())
			require.NoError(t, err)
			return NewBase64Encoder(), store
		},
		"B: hmac + cookie store": func(t *testing.T) (Encoder, Store) { return hmacEnc, NewCookieStore() },
		"D: aes-gcm + file store": func(t *testing.T) (Encoder, Store) {
			store, err := NewFileStore(t.TempDir())
			require.NoError(t, err)
			return aesEnc, store
		},
	}
	for name, config := range configs {
		t.Run(name, func(t *testing.T) {
			encoder, store := config(t)
			transport, err := NewCookieTransport("session", CookieTransportSecure(false))
			require.NoError(t, err)
			m, err := NewManager[testSession](transport, encoder, store)
			require.NoError(t, err)

			mux := http.NewServeMux()

			mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
				sess, err := m.New(r, testSession{UserID: 7})
				if err == nil {
					err = sess.Save(w)
				}
				if err != nil {
					http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
				}
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
					http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
				}
			})

			mux.HandleFunc("GET /me", func(w http.ResponseWriter, r *http.Request) {
				sess, err := m.Load(r)
				if err != nil {
					http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
					return
				}
				v := sess.Values()
				_, _ = w.Write([]byte(http.StatusText(http.StatusOK) + ":" + v.Roles[0]))
			})
			handler := m.Middleware()(mux)

			send := func(method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
				r := httptest.NewRequest(method, path, nil)
				if cookie != nil {
					r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
				}
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, r)
				return rec
			}

			rec := send(http.MethodGet, "/me", nil)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)

			rec = send(http.MethodPost, "/login", nil)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			cookie := responseCookie(t, rec)
			require.NotNil(t, cookie)

			rec = send(http.MethodPost, "/promote", cookie)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			if updated := responseCookie(t, rec); updated != nil {
				cookie = updated // stateless store reissues on update
			}

			rec = send(http.MethodGet, "/me", cookie)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "OK:admin", rec.Body.String())
		})
	}
}

func TestSave_PassesExpiryAndSizeToComponents(t *testing.T) {
	h := newLoadHarness(t, WithLifetime(time.Hour), WithMaxRecordSize(32<<10))
	var credential string
	h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r, testSession{UserID: 1})
		require.NoError(t, err)
		require.NoError(t, sess.Save(w))
		credential = sess.credential
	})
	expires := loadTestNow.Add(time.Hour)
	assert.Equal(t, []StoreParams{{ExpiresAt: expires, MaxRecordSize: 32 << 10}}, h.store.Params(), "Create")
	assert.Equal(t, []TransportParams{{ExpiresAt: expires}}, h.transport.Params(), "Write")

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Set(testSession{UserID: 2}))
		require.NoError(t, sess.Save(w))
	})
	assert.Equal(t, []StoreParams{
		{ExpiresAt: expires, MaxRecordSize: 32 << 10},
		{MaxRecordSize: 32 << 10},                     // Load: expiry not yet known
		{ExpiresAt: expires, MaxRecordSize: 32 << 10}, // Update keeps the expiry
	}, h.store.Params())
}

func TestSession_Timestamps(t *testing.T) {
	h := newLoadHarness(t, WithLifetime(time.Hour))
	credential := h.issue(t, testSession{UserID: 1})

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.True(t, sess.CreatedAt().Equal(loadTestNow.Add(-time.Hour)))
		assert.True(t, sess.ExpiresAt().Equal(loadTestNow.Add(time.Hour)))

		fresh, err := h.manager.New(r, testSession{UserID: 2})
		require.NoError(t, err)
		assert.True(t, fresh.CreatedAt().IsZero(), "not saved yet")
		assert.True(t, fresh.ExpiresAt().IsZero(), "not saved yet")

		require.NoError(t, fresh.Save(w))
		assert.True(t, fresh.CreatedAt().Equal(loadTestNow))
		assert.True(t, fresh.ExpiresAt().Equal(loadTestNow.Add(time.Hour)))
	})
}

func TestExtend_ServerSideStore(t *testing.T) {
	h := newLoadHarness(t, WithLifetime(2*time.Hour))
	meta := envelopeMeta{CreatedAt: loadTestNow.Add(-time.Hour), ExpiresAt: loadTestNow.Add(time.Hour)}
	credential := h.issueWith(t, h.encoder.Encoder, testSession{UserID: 1}, meta)
	extended := loadTestNow.Add(2 * time.Hour)

	var saved *Session[testSession]
	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Extend())
		assert.False(t, sess.IsDirty(), "extending does not change values")
		assert.True(t, sess.ExpiresAt().Equal(extended))
		require.NoError(t, sess.Save(w))
		saved = sess
	})

	assert.Equal(t, []string{"Load", "Update"}, h.store.Calls())
	assert.Equal(t, extended, h.store.Params()[1].ExpiresAt, "store receives the new expiry")
	assert.Equal(t, []TransportParams{{ExpiresAt: extended}}, h.transport.Params(), "credential reissued with the new expiry")
	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie)
	assert.Equal(t, credential, cookie.Value, "server-side credential kept")
	assertCommitted(t, saved)
	assert.ErrorIs(t, saved.Extend(), ErrSessionCommitted)

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.True(t, sess.CreatedAt().Equal(meta.CreatedAt), "creation time kept")
		assert.True(t, sess.ExpiresAt().Equal(extended), "extension persisted")
		assert.Equal(t, 1, sess.Values().UserID)
	})
}

func TestExtend_CookieStore(t *testing.T) {
	h := newTestHarnessWithStore(t, NewCookieStore(), WithLifetime(2*time.Hour))
	h.manager.now = func() time.Time { return loadTestNow }
	credential := h.issue(t, testSession{UserID: 1})

	_, rec := h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Extend())
		require.NoError(t, sess.Save(w))
	})

	cookie := responseCookie(t, rec)
	require.NotNil(t, cookie)
	assert.NotEqual(t, credential, cookie.Value, "the stateless credential carries the new expiry")
	h.do(t, cookieRequest(cookie.Value), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		assert.True(t, sess.ExpiresAt().Equal(loadTestNow.Add(2*time.Hour)))
	})
}

func TestExtend_NewSessionIsNoOp(t *testing.T) {
	h := newLoadHarness(t)
	h.do(t, cookieRequest(), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.New(r)
		require.NoError(t, err)
		require.NoError(t, sess.Extend())
		require.NoError(t, sess.Save(w))
		assert.Equal(t, stateNew, sess.state, "untouched new session still not persisted")
	})
	assert.Empty(t, h.trace.Calls())
}

func TestExtend_UnwritableSession(t *testing.T) {
	h := newLoadHarness(t)
	credential := h.issue(t, testSession{UserID: 1})
	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		replaced, err := h.manager.Load(r)
		require.NoError(t, err)
		_, err = h.manager.New(r)
		require.NoError(t, err)
		assert.ErrorIs(t, replaced.Extend(), ErrSessionReplaced)

		require.NoError(t, h.manager.Delete(w, r))
		assert.ErrorIs(t, replaced.Extend(), ErrSessionDeleted)
	})
}

func TestExtend_RetriedAfterFailedWrite(t *testing.T) {
	h := newLoadHarness(t, WithLifetime(2*time.Hour))
	credential := h.issue(t, testSession{UserID: 1})
	h.transport.FailWith("Write", errors.ErrInternal.Msg("boom"))

	h.do(t, cookieRequest(credential), func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.manager.Load(r)
		require.NoError(t, err)
		require.NoError(t, sess.Extend())
		require.Error(t, sess.Save(w))

		h.transport.FailWith("Write", nil)
		require.NoError(t, sess.Save(w))
	})
	assert.Equal(t, []string{"Read", "Write", "Write"}, h.transport.Calls(), "retry still reissues the credential")
}
