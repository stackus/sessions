package sessions

import (
	"context"
	crand "crypto/rand"
	"io"
	"net/http"

	"github.com/stretchr/testify/mock"
)

func RandomBytes(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		return nil
	}
	return k
}

// mockSessionManager is a mock implementation of SessionManager[T]
type mockSessionManager[T any] struct {
	mock.Mock
}

// Get implements SessionManager[T].Get
func (m *mockSessionManager[T]) Get(r *http.Request, cookieName string) (*Session[T], error) {
	args := m.Called(r, cookieName)

	// Handle the case where no session is returned
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	// Type assert and return the session
	return args.Get(0).(*Session[T]), args.Error(1)
}

// Save implements SessionManager[T].Save
func (m *mockSessionManager[T]) Save(w http.ResponseWriter, r *http.Request, session *Session[T]) error {
	args := m.Called(w, r, session)
	return args.Error(0)
}

// ----------------------------------------------------------------------------

// mockStore is a mock implementation of Store
type mockStore struct {
	mock.Mock
}

// Get implements Store.Get
func (m *mockStore) Get(ctx context.Context, proxy *SessionProxy, value string) error {
	args := m.Called(ctx, proxy, value)
	return args.Error(0)
}

// New implements Store.New
func (m *mockStore) New(ctx context.Context, proxy *SessionProxy) error {
	args := m.Called(ctx, proxy)
	return args.Error(0)
}

// Save implements Store.Save
func (m *mockStore) Save(ctx context.Context, proxy *SessionProxy) error {
	args := m.Called(ctx, proxy)
	return args.Error(0)
}

// ----------------------------------------------------------------------------

type stubStore struct {
	getFn  func(ctx context.Context, proxy *SessionProxy, value string) error
	newFn  func(ctx context.Context, proxy *SessionProxy) error
	saveFn func(ctx context.Context, proxy *SessionProxy) error
}

func (s *stubStore) Get(ctx context.Context, proxy *SessionProxy, value string) error {
	if s.getFn == nil {
		return nil
	}
	return s.getFn(ctx, proxy, value)
}

func (s *stubStore) New(ctx context.Context, proxy *SessionProxy) error {
	if s.newFn == nil {
		return nil
	}
	return s.newFn(ctx, proxy)
}

func (s *stubStore) Save(ctx context.Context, proxy *SessionProxy) error {
	if s.saveFn == nil {
		return nil
	}
	return s.saveFn(ctx, proxy)
}

// ----------------------------------------------------------------------------

// mockCodec is a mock implementation of Codec
type mockCodec struct {
	mock.Mock
}

func (m *mockCodec) Encode(name string, src any) ([]byte, error) {
	args := m.Called(name, src)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockCodec) Decode(name string, src []byte, dst any) error {
	args := m.Called(name, src, dst)
	return args.Error(0)
}

// ----------------------------------------------------------------------------

// stubCodec is a stub implementation of Codec
type stubCodec struct {
	encodeFn func(name string, src any) ([]byte, error)
	decodeFn func(name string, src []byte, dst any) error
}

func (s *stubCodec) Encode(name string, src any) ([]byte, error) {
	if s.encodeFn == nil {
		return nil, nil
	}
	return s.encodeFn(name, src)
}

func (s *stubCodec) Decode(name string, src []byte, dst any) error {
	if s.decodeFn == nil {
		return nil
	}
	return s.decodeFn(name, src, dst)
}

// ----------------------------------------------------------------------------

type mockSessionProxy struct {
	mock.Mock
}

func (m *mockSessionProxy) Write(data []byte, dst any) error {
	args := m.Called(data, dst)
	return args.Error(0)
}

func (m *mockSessionProxy) Read(src any) ([]byte, error) {
	args := m.Called(src)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockSessionProxy) Save(value string) error {
	args := m.Called(value)
	return args.Error(0)
}

func (m *mockSessionProxy) Delete() error {
	args := m.Called()
	return args.Error(0)
}
