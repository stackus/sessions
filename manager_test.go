package sessions

import (
	"math"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager_InvalidArguments(t *testing.T) {
	transport, err := NewCookieTransport("session")
	require.NoError(t, err)
	encoder := NewBase64Encoder()
	store := NewCookieStore()

	tests := map[string]func() (*Manager[testSession], error){
		"nil transport": func() (*Manager[testSession], error) {
			return NewManager[testSession](nil, encoder, store)
		},
		"nil encoder": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, nil, store)
		},
		"nil store": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, nil)
		},
		"typed nil transport": func() (*Manager[testSession], error) {
			return NewManager[testSession]((*CookieTransport)(nil), encoder, store)
		},
		"typed nil encoder": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, (*HMACEncoder)(nil), store)
		},
		"typed nil store": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, (*FileStore)(nil))
		},
		"zero lifetime": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, store, WithLifetime(0))
		},
		"negative lifetime": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, store, WithLifetime(-time.Hour))
		},
		"zero max record size": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, store, WithMaxRecordSize(0))
		},
		"negative max payload size": func() (*Manager[testSession], error) {
			return NewManager[testSession](transport, encoder, store, WithMaxPayloadSize(-1))
		},
	}
	for name, newManager := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := newManager()
			require.Error(t, err)
			assert.Nil(t, m)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
}

func TestNewManager_DefaultsAndOptions(t *testing.T) {
	transport, err := NewCookieTransport("session")
	require.NoError(t, err)

	m, err := NewManager[testSession](transport, NewBase64Encoder(), NewCookieStore())
	require.NoError(t, err)
	assert.Equal(t, managerSettings{
		lifetime:       30 * 24 * time.Hour,
		maxRecordSize:  64 << 10,
		maxPayloadSize: 64 << 10,
	}, m.settings)

	m, err = NewManager[testSession](transport, NewBase64Encoder(), NewCookieStore(),
		WithLifetime(time.Hour), WithMaxRecordSize(1000), WithMaxPayloadSize(2000))
	require.NoError(t, err)
	assert.Equal(t, managerSettings{lifetime: time.Hour, maxRecordSize: 1000, maxPayloadSize: 2000}, m.settings)
}

// §12 example E: insecure, but NewManager does not judge combinations (D5).
func TestNewManager_AcceptsInsecureCombination(t *testing.T) {
	transport, err := NewCookieTransport("session")
	require.NoError(t, err)

	m, err := NewManager[testSession](transport, NewBase64Encoder(), NewCookieStore())
	require.NoError(t, err)
	assert.NotNil(t, m)
}

func TestNextContextKey_NeverWraps(t *testing.T) {
	var counter atomic.Uint32
	counter.Store(math.MaxUint16 - 1)

	k1, err := nextContextKey(&counter)
	require.NoError(t, err)
	assert.Equal(t, contextKey(math.MaxUint16-1), k1)

	k2, err := nextContextKey(&counter)
	require.NoError(t, err)
	assert.Equal(t, contextKey(math.MaxUint16), k2)

	for range 3 {
		k, err := nextContextKey(&counter)
		require.Error(t, err)
		assert.Zero(t, k)
		assert.True(t, errors.Is(err, errors.ErrResourceExhausted))
	}
	assert.Equal(t, uint32(math.MaxUint16+1), counter.Load(), "counter does not advance once exhausted")
}

func TestNewManager_ConcurrentKeysAreUnique(t *testing.T) {
	transport, err := NewCookieTransport("session")
	require.NoError(t, err)

	const n = 64
	keys := make([]contextKey, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			m, err := NewManager[testSession](transport, NewBase64Encoder(), NewCookieStore())
			if assert.NoError(t, err) {
				keys[i] = m.key
			}
		})
	}
	wg.Wait()

	seen := make(map[contextKey]bool)
	for _, k := range keys {
		assert.False(t, seen[k], "duplicate key %d", k)
		seen[k] = true
	}
}

func TestNewManager_FailedValidationDoesNotConsumeKey(t *testing.T) {
	transport, err := NewCookieTransport("session")
	require.NoError(t, err)

	before := managerKeys.Load()
	_, err = NewManager[testSession](transport, nil, NewCookieStore())
	require.Error(t, err)
	_, err = NewManager[testSession](transport, NewBase64Encoder(), NewCookieStore(), WithLifetime(0))
	require.Error(t, err)
	assert.Equal(t, before, managerKeys.Load(), "no key issued for a rejected manager")
}

func TestManager_ScopeRequiresMiddleware(t *testing.T) {
	h := newTestHarness(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	s, err := h.manager.scopeFrom(r)
	assert.Nil(t, s)
	assert.True(t, errors.Is(err, ErrNoScope))
	assert.Equal(t, "SESSION_NO_SCOPE", errors.TypeCode(err))

	s, err = h.manager.scopeFrom(nil)
	assert.Nil(t, s)
	assert.True(t, errors.Is(err, ErrNoScope))
}

func TestManager_MiddlewareInstallsScope(t *testing.T) {
	h := newTestHarness(t)
	original := httptest.NewRequest(http.MethodGet, "/", nil)

	var got *scope[testSession]
	handler := h.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		got, err = h.manager.scopeFrom(r)
		require.NoError(t, err)
		assert.Same(t, r, got.request, "scope holds the derived request")
		assert.Same(t, h.manager, got.manager)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), original)

	require.NotNil(t, got)
	_, err := h.manager.scopeFrom(original)
	assert.True(t, errors.Is(err, ErrNoScope), "the caller's request is not mutated")
}

func TestManager_NestedMiddlewareReusesScope(t *testing.T) {
	h := newTestHarness(t)

	var outer, inner *scope[testSession]
	handler := h.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		outer, _ = h.manager.scopeFrom(r)
		h.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			inner, _ = h.manager.scopeFrom(r)
		})).ServeHTTP(w, r)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.NotNil(t, outer)
	assert.Same(t, outer, inner)
}

func TestManager_TwoManagersHaveIndependentScopes(t *testing.T) {
	first := newTestHarness(t)
	second := newTestHarness(t)

	var s1, s2 *scope[testSession]
	handler := first.manager.Middleware()(second.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		s1, err = first.manager.scopeFrom(r)
		require.NoError(t, err)
		s2, err = second.manager.scopeFrom(r)
		require.NoError(t, err)
	})))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.NotNil(t, s1)
	require.NotNil(t, s2)
	assert.NotSame(t, s1, s2)
	assert.Same(t, first.manager, s1.manager)
	assert.Same(t, second.manager, s2.manager)
}

func TestManager_MiddlewareDoesNoSessionWork(t *testing.T) {
	h := newTestHarness(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "session", Value: "presented-credential"})
	rec := httptest.NewRecorder()

	handler := h.manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(rec, r)

	assert.Empty(t, h.componentCalls(), "no transport, encoder, or store calls")
	assert.Empty(t, rec.Header().Values("Set-Cookie"))
	assert.Equal(t, http.StatusNoContent, rec.Code)
}

func TestIsNil(t *testing.T) {
	var nilMap map[string]int
	var nilFunc func()
	var nilPointer *FileStore
	tests := map[string]struct {
		v    any
		want bool
	}{
		"untyped nil": {v: nil, want: true},
		"nil pointer": {v: nilPointer, want: true},
		"nil map":     {v: nilMap, want: true},
		"nil func":    {v: nilFunc, want: true},
		"pointer":     {v: &FileStore{}, want: false},
		"value":       {v: Base64Encoder{}, want: false},
		"int":         {v: 0, want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, isNil(tc.v))
		})
	}
}
