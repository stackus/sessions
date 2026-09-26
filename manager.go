package sessions

import (
	"context"
	"math"
	"net/http"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/stackus/errors"
)

// Manager loads, creates, and deletes sessions holding values of type T. It
// owns the transport, encoder, and store, and installs the per-request scope
// through Middleware.
//
// A Manager is safe for concurrent use. Sessions themselves are
// request-scoped.
type Manager[T any] struct {
	transport Transport
	encoder   Encoder
	store     Store
	key       contextKey
	now       func() time.Time
	settings  managerSettings
}

// ManagerOption configures a Manager.
type ManagerOption func(*managerSettings)

type managerSettings struct {
	lifetime       time.Duration
	maxRecordSize  int
	maxPayloadSize int
}

// WithLifetime sets the absolute session lifetime, measured from when a
// session is first saved. Loading a session never extends it. The default is
// 30 days. Session.Extend restarts it from the time of the call.
//
// The manager passes each session's expiry to the store and transport, so
// they need no lifetime of their own.
func WithLifetime(d time.Duration) ManagerOption {
	return func(s *managerSettings) { s.lifetime = d }
}

// WithMaxRecordSize sets the largest encoded record, in bytes, that the
// manager writes to or accepts from the store. The default is 64 KiB.
func WithMaxRecordSize(n int) ManagerOption {
	return func(s *managerSettings) { s.maxRecordSize = n }
}

// WithMaxPayloadSize sets the largest serialized session, in bytes, before
// encoding or after decoding. The default is 64 KiB.
func WithMaxPayloadSize(n int) ManagerOption {
	return func(s *managerSettings) { s.maxPayloadSize = n }
}

// NewManager returns a Manager that carries credentials with transport,
// encodes records with encoder, and persists them in store.
//
// All three components are required. NewManager does not judge whether a
// combination is secure; for example, CookieStore with Base64Encoder is
// accepted even though the client could forge its session. See each
// component's documentation.
//
// It returns an errors.ErrInvalidArgument error for a nil component or a
// non-positive option value, and an errors.ErrResourceExhausted error once
// 65,536 managers have been created in the process.
func NewManager[T any](transport Transport, encoder Encoder, store Store, opts ...ManagerOption) (*Manager[T], error) {
	switch {
	case isNil(transport):
		return nil, errors.ErrInvalidArgument.Msg("sessions: transport is nil")
	case isNil(encoder):
		return nil, errors.ErrInvalidArgument.Msg("sessions: encoder is nil")
	case isNil(store):
		return nil, errors.ErrInvalidArgument.Msg("sessions: store is nil")
	}

	settings := managerSettings{
		lifetime:       defaultLifetime,
		maxRecordSize:  defaultMaxRecordSize,
		maxPayloadSize: defaultMaxPayloadSize,
	}

	for _, opt := range opts {
		opt(&settings)
	}

	switch {
	case settings.lifetime <= 0:
		return nil, errors.ErrInvalidArgument.Msgf("sessions: lifetime must be positive, got %s", settings.lifetime)
	case settings.maxRecordSize <= 0:
		return nil, errors.ErrInvalidArgument.Msgf("sessions: max record size must be positive, got %d", settings.maxRecordSize)
	case settings.maxPayloadSize <= 0:
		return nil, errors.ErrInvalidArgument.Msgf("sessions: max payload size must be positive, got %d", settings.maxPayloadSize)
	}

	key, err := nextContextKey(&managerKeys)
	if err != nil {
		return nil, err
	}

	return &Manager[T]{
		transport: transport,
		encoder:   encoder,
		store:     store,
		key:       key,
		now:       time.Now,
		settings:  settings,
	}, nil
}

// Middleware returns middleware that installs this manager's request scope.
// Every Manager method that takes a request requires it and returns
// ErrNoScope without it.
//
// The middleware does no session work of its own: it does not read the
// credential, touch the store, or create a session. If the request already
// carries this manager's scope, it is reused.
func (m *Manager[T]) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.Context().Value(m.key).(*scope[T]); ok {
				next.ServeHTTP(w, r)
				return
			}
			s := &scope[T]{manager: m}
			r = r.WithContext(context.WithValue(r.Context(), m.key, s))
			s.request = r
			next.ServeHTTP(w, r)
		})
	}
}

// scopeFrom returns this manager's scope for r, or ErrNoScope.
func (m *Manager[T]) scopeFrom(r *http.Request) (*scope[T], error) {
	if r != nil {
		if s, ok := r.Context().Value(m.key).(*scope[T]); ok {
			return s, nil
		}
	}
	return nil, ErrNoScope.Msg("sessions: scope is not installed; wrap the route with Manager.Middleware")
}

// contextKey identifies one manager's scope in a request context.
type contextKey uint16

// managerKeys counts the context keys issued so far.
var managerKeys atomic.Uint32

// nextContextKey issues the next unused key from counter. Once every uint16
// value has been issued it returns an error rather than wrapping around to a
// key that is already in use.
func nextContextKey(counter *atomic.Uint32) (contextKey, error) {
	for {
		n := counter.Load()
		if n > math.MaxUint16 {
			return 0, errors.ErrResourceExhausted.Msg("sessions: all 65536 manager context keys are in use")
		}
		if counter.CompareAndSwap(n, n+1) {
			return contextKey(n), nil
		}
	}
}

// isNil reports whether v is nil, including a nil pointer, map, slice,
// function, or channel stored in an interface.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	switch rv := reflect.ValueOf(v); rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}

	return false
}
