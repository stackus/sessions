package sessions

import (
	"net/http"
)

type SessionManager[T any] interface {
	Get(r *http.Request) (*Session[T], error)
	Save(w http.ResponseWriter, r *http.Request, session *Session[T]) error
}

type sessionManager[T any] struct {
	options CookieOptions
	store   Store
	codecs  []Codec
}

func NewSessionManager[T any](options CookieOptions, store Store, codecs ...Codec) SessionManager[T] {
	return &sessionManager[T]{
		options: options,
		store:   store,
		codecs:  codecs,
	}
}

// Get returns a session for the given request and cookie name.
//
// The returned session will inherit the options set in the manager.
func (sm *sessionManager[T]) Get(r *http.Request) (*Session[T], error) {
	reg := getRegistry(r)
	if session := reg.get(sm.options.Name); session != nil {
		if s, ok := session.(*Session[T]); ok {
			return s, nil
		}
		return nil, ErrInvalidSessionType
	}

	proxy := &SessionProxy{
		Values:  new(T),
		req:     r,
		options: &sm.options,
		codecs:  sm.codecs,
	}

	if initable, ok := proxy.Values.(interface{ Init() }); ok {
		initable.Init()
	}

	var err error
	if c, cErr := r.Cookie(sm.options.Name); cErr == nil {
		err = sm.store.Get(r.Context(), proxy, c.Value)
	} else {
		// start with IsNew = true; if the store needs or wants to set it to false, it may
		proxy.IsNew = true
		err = sm.store.New(r.Context(), proxy)
	}

	if err != nil {
		return nil, err
	}

	values, ok := proxy.Values.(*T)
	if !ok {
		return nil, ErrInvalidSessionType
	}

	session := &Session[T]{
		Values:   *values,
		IsNew:    proxy.IsNew,
		storeKey: proxy.ID,
		manager:  sm,
		options:  *proxy.options,
	}

	reg.set(sm.options.Name, session)

	return session, nil
}

func (sm *sessionManager[T]) Save(w http.ResponseWriter, r *http.Request, session *Session[T]) error {
	proxy := &SessionProxy{
		req:     r,
		resp:    w,
		options: &session.options,
		codecs:  sm.codecs,
		Values:  session.Values,
		ID:      session.storeKey,
		IsNew:   session.IsNew,
	}

	return sm.store.Save(r.Context(), proxy)
}
