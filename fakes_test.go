package sessions

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// callRecorder records method calls in order and injects per-method errors.
// When trace is set, each call is also appended to it as "name.Method", giving
// the order of calls across components.
type callRecorder struct {
	mu    sync.Mutex
	calls []string
	errs  map[string]error
	name  string
	trace *callRecorder
}

func (c *callRecorder) record(method string) error {
	if c.trace != nil {
		_ = c.trace.record(c.name + "." + method)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, method)
	return c.errs[method]
}

// Calls returns the methods called so far, in order.
func (c *callRecorder) Calls() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

// FailWith makes every later call to method return err.
func (c *callRecorder) FailWith(method string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.errs == nil {
		c.errs = make(map[string]error)
	}
	c.errs[method] = err
}

// recordingStore wraps a real Store.
type recordingStore struct {
	callRecorder
	Store
	params []StoreParams // params of every Load, Create, and Update, in order
}

func (s *recordingStore) recordParams(p StoreParams) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.params = append(s.params, p)
}

// Params returns the params passed so far, in order.
func (s *recordingStore) Params() []StoreParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]StoreParams(nil), s.params...)
}

func (s *recordingStore) Load(ctx context.Context, credential string, params StoreParams) ([]byte, error) {
	s.recordParams(params)
	if err := s.record("Load"); err != nil {
		return nil, err
	}
	return s.Store.Load(ctx, credential, params)
}

func (s *recordingStore) Create(ctx context.Context, data []byte, params StoreParams) (string, error) {
	s.recordParams(params)
	if err := s.record("Create"); err != nil {
		return "", err
	}
	return s.Store.Create(ctx, data, params)
}

func (s *recordingStore) Update(ctx context.Context, credential string, data []byte, params StoreParams) (string, error) {
	s.recordParams(params)
	if err := s.record("Update"); err != nil {
		return "", err
	}
	return s.Store.Update(ctx, credential, data, params)
}

func (s *recordingStore) Delete(ctx context.Context, credential string) error {
	if err := s.record("Delete"); err != nil {
		return err
	}
	return s.Store.Delete(ctx, credential)
}

// recordingTransport wraps a real Transport.
type recordingTransport struct {
	callRecorder
	Transport
	params []TransportParams // params of every Write, in order
}

// Params returns the params passed to Write so far, in order.
func (t *recordingTransport) Params() []TransportParams {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]TransportParams(nil), t.params...)
}

func (t *recordingTransport) Read(r *http.Request) (string, error) {
	if err := t.record("Read"); err != nil {
		return "", err
	}
	return t.Transport.Read(r)
}

func (t *recordingTransport) Write(w http.ResponseWriter, r *http.Request, credential string, params TransportParams) error {
	t.mu.Lock()
	t.params = append(t.params, params)
	t.mu.Unlock()
	if err := t.record("Write"); err != nil {
		return err
	}
	return t.Transport.Write(w, r, credential, params)
}

func (t *recordingTransport) Clear(w http.ResponseWriter, r *http.Request) error {
	if err := t.record("Clear"); err != nil {
		return err
	}
	return t.Transport.Clear(w, r)
}

// recordingEncoder wraps a real Encoder. It deliberately does not implement
// RefreshDecoder; wrap a RotatingEncoder directly when a test needs that.
type recordingEncoder struct {
	callRecorder
	Encoder
}

func (e *recordingEncoder) Encode(data []byte) ([]byte, error) {
	if err := e.record("Encode"); err != nil {
		return nil, err
	}
	return e.Encoder.Encode(data)
}

func (e *recordingEncoder) Decode(data []byte) ([]byte, error) {
	if err := e.record("Decode"); err != nil {
		return nil, err
	}
	return e.Encoder.Decode(data)
}

// testSession is the session value type used by manager tests.
type testSession struct {
	UserID int      `json:"user_id"`
	Roles  []string `json:"roles"`
}

// testHarness is a manager built from recording wrappers around real
// components: a cookie transport, an HMAC encoder, and a file store.
type testHarness struct {
	manager   *Manager[testSession]
	transport *recordingTransport
	encoder   *recordingEncoder
	store     *recordingStore
	trace     *callRecorder // every component call, in order
}

func newTestHarness(t *testing.T, opts ...ManagerOption) *testHarness {
	t.Helper()
	fileStore, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	return newTestHarnessWithStore(t, fileStore, opts...)
}

func newTestHarnessWithStore(t *testing.T, store Store, opts ...ManagerOption) *testHarness {
	t.Helper()
	cookie, err := NewCookieTransport("session", CookieTransportSecure(false))
	require.NoError(t, err)
	hmacEnc, err := NewHMACEncoder(randomBytes(t, 32))
	require.NoError(t, err)

	trace := &callRecorder{}
	h := &testHarness{
		transport: &recordingTransport{callRecorder: callRecorder{name: "transport", trace: trace}, Transport: cookie},
		encoder:   &recordingEncoder{callRecorder: callRecorder{name: "encoder", trace: trace}, Encoder: hmacEnc},
		store:     &recordingStore{callRecorder: callRecorder{name: "store", trace: trace}, Store: store},
		trace:     trace,
	}
	h.manager, err = NewManager[testSession](h.transport, h.encoder, h.store, opts...)
	require.NoError(t, err)
	return h
}

// componentCalls returns every transport, encoder, and store call, in order
// within each component.
func (h *testHarness) componentCalls() []string {
	var calls []string
	calls = append(calls, h.transport.Calls()...)
	calls = append(calls, h.encoder.Calls()...)
	calls = append(calls, h.store.Calls()...)
	return calls
}
