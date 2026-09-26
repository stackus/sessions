package sessions_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/stackus/errors"

	"github.com/stackus/sessions"
)

type SessionData struct {
	UserID int    `json:"user_id"`
	Theme  string `json:"theme"`
}

// mustKey returns n random bytes. Real applications load their keys from
// configuration or a secret manager.
func mustKey(n int) []byte {
	key := make([]byte, n)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	return key
}

// The basic pattern: load the session, create one explicitly if there is
// none, change it, and save it before writing the response.
func Example() {
	transport, err := sessions.NewCookieTransport("session", sessions.CookieTransportSecure(false))
	if err != nil {
		log.Fatal(err)
	}
	encoder, err := sessions.NewHMACEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	manager, err := sessions.NewManager[SessionData](transport, encoder, sessions.NewCookieStore())
	if err != nil {
		log.Fatal(err)
	}

	updateTheme := func(w http.ResponseWriter, r *http.Request) {
		sess, err := manager.LoadOrNew(r) // the existing session, or a new one
		if err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		if err := sess.Update(func(v *SessionData) { v.Theme = "dark" }); err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		if err := sess.Save(w); err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	showTheme := func(w http.ResponseWriter, r *http.Request) {
		theme := "light"
		sess, err := manager.Load(r)
		switch {
		case err == nil:
			theme = sess.Values().Theme
		case !sessions.IsNoSession(err):
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		_, _ = io.WriteString(w, theme)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /theme", updateTheme)
	mux.HandleFunc("GET /theme", showTheme)
	handler := manager.Middleware()(mux)

	// First request: no session yet, so one is created and saved.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/theme", nil))
	cookie := rec.Result().Cookies()[0]

	// Second request presents the cookie.
	r := httptest.NewRequest(http.MethodGet, "/theme", nil)
	r.AddCookie(cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	fmt.Println(rec.Body.String())
	// Output: dark
}

// A browser cookie holding an opaque random ID, with the
// session data on the server. No key is needed.
func ExampleNewManager_fileStore() {
	dir, err := os.MkdirTemp("", "sessions")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	transport, err := sessions.NewCookieTransport("session")
	if err != nil {
		log.Fatal(err)
	}
	store, err := sessions.NewFileStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	_, err = sessions.NewManager[SessionData](transport, sessions.NewBase64Encoder(), store)
	fmt.Println(err)
	// Output: <nil>
}

// A stateless, signed browser cookie. HMAC stops clients from
// changing the session but does not hide it from them.
func ExampleNewManager_signedCookie() {
	transport, err := sessions.NewCookieTransport("session")
	if err != nil {
		log.Fatal(err)
	}
	encoder, err := sessions.NewHMACEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	_, err = sessions.NewManager[SessionData](transport, encoder, sessions.NewCookieStore())
	fmt.Println(err)
	// Output: <nil>
}

// A CLI or API client sends "Authorization: Bearer <token>"
// and receives tokens in an App-Token response header.
func ExampleNewManager_bearer() {
	dir, err := os.MkdirTemp("", "sessions")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	transport, err := sessions.NewBearerTransport(sessions.BearerTransportTokenHeader("App-Token"))
	if err != nil {
		log.Fatal(err)
	}
	store, err := sessions.NewFileStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	manager, err := sessions.NewManager[SessionData](transport, sessions.NewBase64Encoder(), store)
	if err != nil {
		log.Fatal(err)
	}

	login := manager.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := manager.New(r, SessionData{UserID: 42})
		if err == nil {
			err = sess.Save(w)
		}
		if err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
		}
	}))
	rec := httptest.NewRecorder()
	login.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/login", nil))
	fmt.Println(rec.Header().Get("App-Token") != "", rec.Header().Get("Cache-Control"))
	// Output: true no-store
}

// Session data on the server, encrypted at rest.
func ExampleNewManager_encryptedFileStore() {
	dir, err := os.MkdirTemp("", "sessions")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	transport, err := sessions.NewCookieTransport("session")
	if err != nil {
		log.Fatal(err)
	}
	encoder, err := sessions.NewAESGCMEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	store, err := sessions.NewFileStore(dir)
	if err != nil {
		log.Fatal(err)
	}
	_, err = sessions.NewManager[SessionData](transport, encoder, store)
	fmt.Println(err)
	// Output: <nil>
}

// Rotating keys: encode with the new key, keep accepting the old one, and let
// Save re-encode old sessions.
func ExampleNewRotatingEncoder() {
	oldKey, err := sessions.NewAESGCMEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	newKey, err := sessions.NewAESGCMEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	encoder, err := sessions.NewRotatingEncoder(newKey, oldKey)
	if err != nil {
		log.Fatal(err)
	}

	fromOldKey, err := oldKey.Encode([]byte("record"))
	if err != nil {
		log.Fatal(err)
	}
	decoded, refresh, err := encoder.DecodeWithRefresh(fromOldKey)
	fmt.Println(string(decoded), refresh, err)
	// Output: record true <nil>
}

// Protecting routes: onFailure runs only when there is no usable session;
// store failures still produce an error response.
func ExampleRequireSession() {
	transport, err := sessions.NewCookieTransport("session", sessions.CookieTransportSecure(false))
	if err != nil {
		log.Fatal(err)
	}
	encoder, err := sessions.NewHMACEncoder(mustKey(32))
	if err != nil {
		log.Fatal(err)
	}
	manager, err := sessions.NewManager[SessionData](transport, encoder, sessions.NewCookieStore())
	if err != nil {
		log.Fatal(err)
	}

	toLogin := http.RedirectHandler("/login", http.StatusSeeOther)
	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "dashboard")
	})
	handler := manager.Middleware()(sessions.RequireSession(manager, toLogin)(dashboard))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	fmt.Println(rec.Code, rec.Header().Get("Location"))
	// Output: 303 /login
}
