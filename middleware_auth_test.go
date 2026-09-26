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

// helperOutcome reports which handler a helper ran.
type helperOutcome string

const (
	ranNext      helperOutcome = "next"
	ranOnFailure helperOutcome = "onFailure"
	ranNeither   helperOutcome = "neither"
)

// runHelper sends r through helper (wrapped in the manager's middleware unless
// withoutScope) and reports which handler ran.
func runHelper(h *testHarness, helper func(http.Handler) http.Handler, r *http.Request, withoutScope bool) (helperOutcome, *httptest.ResponseRecorder) {
	outcome := ranNeither
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { outcome = ranNext })
	handler := helper(next)
	if !withoutScope {
		handler = h.manager.Middleware()(handler)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	return outcome, rec
}

func TestAuthHelpers(t *testing.T) {
	type scenario struct {
		request      func(t *testing.T, h *testHarness) *http.Request
		withoutScope bool
		storeFails   bool
	}
	scenarios := map[string]scenario{
		"no credential": {request: func(t *testing.T, h *testHarness) *http.Request { return cookieRequest() }},
		"invalid credential": {request: func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest("garbage")
		}},
		"expired session": {request: func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest(h.issueWith(t, h.encoder.Encoder, testSession{UserID: 1}, envelopeMeta{
				CreatedAt: loadTestNow.Add(-2 * time.Hour), ExpiresAt: loadTestNow.Add(-time.Hour),
			}))
		}},
		"missing record": {request: func(t *testing.T, h *testHarness) *http.Request {
			credential := h.issue(t, testSession{UserID: 1})
			require.NoError(t, h.store.Store.Delete(t.Context(), credential))
			return cookieRequest(credential)
		}},
		"valid session": {request: func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest(h.issue(t, testSession{UserID: 1}))
		}},
		"valid session, check fails": {request: func(t *testing.T, h *testHarness) *http.Request {
			return cookieRequest(h.issue(t, testSession{UserID: 2}))
		}},
		"store failure": {
			request: func(t *testing.T, h *testHarness) *http.Request {
				return cookieRequest(h.issue(t, testSession{UserID: 1}))
			},
			storeFails: true,
		},
		"missing middleware": {
			request: func(t *testing.T, h *testHarness) *http.Request {
				return cookieRequest(h.issue(t, testSession{UserID: 1}))
			},
			withoutScope: true,
		},
	}

	onFailureRan := func(outcome *helperOutcome) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			*outcome = ranOnFailure
			w.WriteHeader(http.StatusSeeOther)
		})
	}
	isUserOne := func(sess *Session[testSession]) bool { return sess.Values().UserID == 1 }

	helpers := map[string]struct {
		build func(m *Manager[testSession], onFailure http.Handler) func(http.Handler) http.Handler
		want  map[string]helperOutcome
	}{
		"RequireSession": {
			build: func(m *Manager[testSession], onFailure http.Handler) func(http.Handler) http.Handler {
				return RequireSession(m, onFailure)
			},
			want: map[string]helperOutcome{
				"no credential": ranOnFailure, "invalid credential": ranOnFailure, "expired session": ranOnFailure,
				"missing record": ranOnFailure, "valid session": ranNext, "valid session, check fails": ranNext,
				"store failure": ranNeither, "missing middleware": ranNeither,
			},
		},
		"RequireSessionState": {
			build: func(m *Manager[testSession], onFailure http.Handler) func(http.Handler) http.Handler {
				return RequireSessionState(m, isUserOne, onFailure)
			},
			want: map[string]helperOutcome{
				"no credential": ranOnFailure, "invalid credential": ranOnFailure, "expired session": ranOnFailure,
				"missing record": ranOnFailure, "valid session": ranNext, "valid session, check fails": ranOnFailure,
				"store failure": ranNeither, "missing middleware": ranNeither,
			},
		},
		"GuestOnly": {
			build: func(m *Manager[testSession], onFailure http.Handler) func(http.Handler) http.Handler {
				return GuestOnly(m, onFailure)
			},
			want: map[string]helperOutcome{
				"no credential": ranNext, "invalid credential": ranNext, "expired session": ranNext,
				"missing record": ranNext, "valid session": ranOnFailure, "valid session, check fails": ranOnFailure,
				"store failure": ranNeither, "missing middleware": ranNeither,
			},
		},
	}

	for helperName, helper := range helpers {
		for scenarioName, sc := range scenarios {
			t.Run(helperName+"/"+scenarioName, func(t *testing.T) {
				h := newLoadHarness(t)
				r := sc.request(t, h)
				if sc.storeFails {
					h.store.FailWith("Load", errors.ErrInternal.Msg("disk failure at /var/lib/sessions"))
				}

				failureOutcome := ranNeither
				outcome, rec := runHelper(h, helper.build(h.manager, onFailureRan(&failureOutcome)), r, sc.withoutScope)
				if failureOutcome == ranOnFailure {
					outcome = ranOnFailure
				}

				want := helper.want[scenarioName]
				assert.Equal(t, want, outcome)
				if want == ranNeither {
					assert.Equal(t, http.StatusInternalServerError, rec.Code)
					assert.Equal(t, "Internal Server Error", strings.TrimSpace(rec.Body.String()))
					assert.NotContains(t, rec.Body.String(), "/var/lib", "internal detail not exposed")
				}
			})
		}
	}
}

func TestRequireSessionState_CheckNotCalledWithoutSession(t *testing.T) {
	h := newLoadHarness(t)
	called := false
	check := func(*Session[testSession]) bool { called = true; return true }
	outcome, _ := runHelper(h, RequireSessionState(h.manager, check, http.NotFoundHandler()), cookieRequest(), false)
	assert.Equal(t, ranNeither, outcome, "next not run")
	assert.False(t, called)
}

func TestRequireSession_NewSessionCountsAsPresent(t *testing.T) {
	h := newLoadHarness(t)
	create := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.manager.New(r)
			require.NoError(t, err)
			next.ServeHTTP(w, r)
		})
	}
	outcome, _ := runHelper(h, func(next http.Handler) http.Handler {
		return create(RequireSession(h.manager, http.NotFoundHandler())(next))
	}, cookieRequest(), false)
	assert.Equal(t, ranNext, outcome)
}

func TestAuthHelpers_OnFailureCanInspectAndClear(t *testing.T) {
	h := newLoadHarness(t)
	onFailure := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := h.manager.Load(r)
		assert.ErrorIs(t, err, ErrInvalidSession, "cached outcome visible to onFailure")
		assert.NoError(t, h.manager.Delete(w, r))
		w.WriteHeader(http.StatusUnauthorized)
	})

	_, rec := runHelper(h, RequireSession(h.manager, onFailure), cookieRequest("garbage"), false)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assertCleared(t, rec)
}
