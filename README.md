# Sessions

Type-safe HTTP sessions for Go, with an explicit lifecycle and interchangeable transports, stores, and encoders.

[![Go Reference](https://pkg.go.dev/badge/github.com/stackus/sessions.svg)](https://pkg.go.dev/github.com/stackus/sessions)
[![Go Report Card](https://goreportcard.com/badge/github.com/stackus/sessions)](https://goreportcard.com/report/github.com/stackus/sessions)
[![Coverage Status](https://coveralls.io/repos/stackus/sessions/badge.png)](https://coveralls.io/r/stackus/sessions)
![Test Status](https://github.com/stackus/sessions/actions/workflows/test.yaml/badge.svg)

> Upgrading from v0.4? The API has changed completely. See [MIGRATION.md](MIGRATION.md).

## Features

- **Type-safe values:** a session holds a value of your own type `T`.
- **Nothing implicit:** a session is never created or saved behind your back. A request that doesn't use sessions does no session work.
- **Saves only what changed:** unchanged sessions are not rewritten, and credentials are only issued when they are new or changed.
- **Clear failure handling:** "no usable session" (missing, invalid, expired, deleted) is distinct from operational failures such as an unreachable store, which are never hidden.
- **Interchangeable components:** cookie or bearer-token transports; stateless cookie or server-side file stores; Base64, HMAC, or AES-GCM encoders; key rotation.
- **Several sessions per request:** each manager keeps its own request scope.

Sessions manage session data only. Authentication, authorization, and CSRF protection are your application's responsibility.

## Requirements

- Go 1.26 or later.

```sh
go get github.com/stackus/sessions
```

## Quick start

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/stackus/errors"
	"github.com/stackus/sessions"
)

type SessionData struct {
	UserID int
	Role   string
	Theme  string
}

func main() {
	transport, err := sessions.NewCookieTransport("session")
	if err != nil {
		log.Fatal(err)
	}
	signingKey := []byte(os.Getenv("SESSION_SIGNING_KEY"))
	encoder, err := sessions.NewHMACEncoder(signingKey) // at least 32 random bytes
	if err != nil {
		log.Fatal(err)
	}
	manager, err := sessions.NewManager[SessionData](transport, encoder, sessions.NewCookieStore())
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /theme", func(w http.ResponseWriter, r *http.Request) {
		sess, err := manager.LoadOrNew(r) // existing session, or a new one
		if err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		if err := sess.Update(func(v *SessionData) { v.Theme = "dark" }); err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		// Save before writing anything to the response.
		if err := sess.Save(w); err != nil {
			http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})

	// Every route that uses sessions needs the manager's middleware.
	log.Fatal(http.ListenAndServe(":8080", manager.Middleware()(mux)))
}
```

## How sessions work

A `Manager[T]` combines three components: a **transport**, an **encoder**, and a **store**. Wrap your routes with `manager.Middleware()`, which installs a per-request scope and does nothing else.

| Call | What it does |
| --- | --- |
| `manager.Load(r)` | Returns the request's existing session. **Never creates one.** When there is none, it returns an error for which `sessions.IsNoSession(err)` is true. |
| `manager.New(r)` / `manager.New(r, v)` | Creates a session in memory only. With an initial value it is already marked as changed. |
| `manager.LoadOrNew(r)` | Returns the existing session, or a new in-memory one when there is none. Any error it returns is an operational failure. |
| `sess.Values()` | Returns a shallow copy of the values. |
| `sess.Set(v)` / `sess.Update(func(*T))` | Change the values and mark the session as changed. |
| `sess.IsNew()` / `sess.IsDirty()` / `sess.IsCommitted()` | Not yet persisted / changed since loaded or saved / `Save` has succeeded. |
| `sess.Save(w)` | Commits once: persists the session if it changed and issues its credential if it is new or changed. |
| `sess.CreatedAt()` / `sess.ExpiresAt()` | When the session was first saved and when it expires; zero before the first save. |
| `sess.Extend()` | Restarts the lifetime from now. `Save` rewrites the record and reissues the credential with the new expiry. |
| `manager.Delete(w, r)` / `sess.Delete(w)` | Deletes the session and clears its credential, without needing to decode it. |

Things to know:

- **`Load` is cached per request.** Repeated calls return the same session, and `Load` after `New` returns the new session.
- **`Save` is a one-time commit.** Make all changes first. Afterwards, `Set`, `Update`, and `Delete` return `ErrSessionCommitted`, and `Save` does nothing. If `Save` fails, the session keeps its changes, so you can report the error or retry.
- **An untouched `New` is not saved.** `New(r)` followed by `Save` stores nothing unless you changed the values.
- **`New` after `Load` replaces the session.** Saving the new session issues a new credential and then deletes the old record. Do this when a login raises privileges. `New` without a prior `Load` leaves the old record in place until it expires.
- **`Load` does not clear a rejected credential.** Call `manager.Delete(w, r)` to clear it, or save a new session to replace it.
- **Lifetime is absolute unless you extend it.** It counts from when the session is first saved, and reading a session never extends it. Call `Extend` to restart it, for example when less than half is left:

  ```go
  if time.Until(sess.ExpiresAt()) < lifetime/2 {
  	_ = sess.Extend()
  }
  if err := sess.Save(w); err != nil { /* ... */ }
  ```

  Extending on every request writes to the store on every request. Compare `CreatedAt` if you also want an absolute limit.
- **The manager owns lifetime and record size.** It passes each session's expiry and the record size limit to the store and transport, so they need no settings of their own.

### Errors

Errors are [`github.com/stackus/errors`](https://github.com/stackus/errors) kinds. Every error carries an HTTP status and a message that is safe to show to clients, so a handler can always respond with:

```go
http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
```

| Error | Type code | HTTP | Public message | `IsNoSession` |
| --- | --- | --- | --- | --- |
| `ErrNoSession` | `SESSION_NONE` | 401 | A session is required | true |
| `ErrInvalidSession` | `SESSION_INVALID` | 401 | The session is invalid | true |
| `ErrSessionExpired` | `SESSION_EXPIRED` | 401 | The session has expired | true |
| `ErrSessionNotFound` | `SESSION_NOT_FOUND` | 401 | The session is invalid | true |
| `ErrSessionDeleted` | `SESSION_DELETED` | 401 | The session has ended | true |
| `ErrNoScope` | `SESSION_NO_SCOPE` | 500 | Internal Server Error | false |
| `ErrSessionCommitted` | `SESSION_COMMITTED` | 500 | Internal Server Error | false |
| `ErrSessionReplaced` | `SESSION_REPLACED` | 500 | Internal Server Error | false |
| `ErrInvalidEncoding` | `SESSION_INVALID_ENCODING` | 400 | Bad Request | false |
| `ErrNoCredential` | `SESSION_NO_CREDENTIAL` | 401 | Unauthorized | false |

`ErrInvalidEncoding` and `ErrNoCredential` are signals from encoders and transports; the manager reports them as `ErrInvalidSession` and `ErrNoSession`. Operational failures, such as I/O errors or a failing random source, use the package's built-in categories (for example `errors.ErrInternal`), and `IsNoSession` reports false for them.

Messages never include credentials, keys, or session values.

## Components

Every constructor that validates its configuration returns an error; none of them panic.

### Transports

**`CookieTransport`**, for browsers.

```go
transport, err := sessions.NewCookieTransport("session",
	sessions.CookieTransportPath("/"),
)
```

Defaults: 
- Path `/`
- no Domain 
- `Secure`
- `HttpOnly`
- `SameSite=Lax`
- not Partitioned
- persistent: the cookie expires together with the session
- 4096-byte maximum credential 

Options: 
- `CookieTransportPath`
- `CookieTransportDomain`
- `CookieTransportSecure`
- `CookieTransportHTTPOnly`
- `CookieTransportSameSite`
- `CookieTransportPartitioned`
- `CookieTransportPersistent`
- `CookieTransportMaxCredentialSize`

- `Secure` is on by default. For local development over plain HTTP, pass `CookieTransportSecure(false)`.
- The cookie's `Expires` and `Max-Age` come from the session's expiry, and follow it when the session is extended. `CookieTransportPersistent(false)` makes a browser-session cookie instead, dropped when the browser closes; the session still expires on the server.
- `Partitioned` and `SameSite=None` require `Secure`.
- Clearing expires the cookie with the same name, path, and domain. A duplicate cookie left behind under another path is reported as ambiguous (`ErrInvalidSession`) until it expires.

**`BearerTransport`**, for CLI and API clients.

```go
transport, err := sessions.NewBearerTransport(sessions.BearerTransportTokenHeader("App-Token"))
```

- Reads `Authorization: Bearer <token>`. Another scheme, such as `Basic`, counts as no credential.
- Issues tokens in a response header, `Session-Token` by default, with `Cache-Control: no-store`. A token is only issued when it is new or changed, or the session was extended.
- Clearing sends `<header>-Action: clear`. **The client must delete its stored token itself.**
- If one response both clears and issues (logout, then a new session), only the last one is sent.
- Browser JavaScript clients need the headers listed in `Access-Control-Expose-Headers`.

### Encoders

| Encoder | Confidentiality | Integrity | Use with |
| --- | --- | --- | --- |
| `NewBase64Encoder()` | no | no | server-side stores in a trusted environment |
| `NewHMACEncoder(key)` | **no**, clients can read it | yes | cookie stores whose values may be visible |
| `NewAESGCMEncoder(key)` | yes | yes | anything that must stay private |

- **HMAC is not encryption.** The data stays readable. `NewHMACEncoder` requires a key of at least 32 bytes.
- `NewAESGCMEncoder` takes a 16-, 24-, or 32-byte key and uses a fresh random nonce for every record.
- Both accept `sessions.WithEncoderLabel("name")`. The label is authenticated but not stored, so managers that share a key cannot accept each other's records.
- **Key rotation:** `sessions.NewRotatingEncoder(current, previous...)` encodes with `current` and also accepts data from the previous encoders. A session loaded with an old key is re-encoded with the current key on its next `Save`, even if nothing changed. A rotating encoder is only as strong as the weakest encoder it accepts.

### Stores

**`CookieStore`** keeps the whole encoded record in the client's credential, so nothing is stored on the server.

- It requires an authenticating encoder: HMAC, AES-GCM, or a rotating encoder of those.
- Deleting or replacing a session cannot revoke copies of an old credential. They stay valid until they expire.
- Watch the cookie size limit: the credential must fit in `CookieTransportMaxCredentialSize` (4096 bytes by default).

**`FileStore`** keeps each record in its own file, named after a 256-bit random ID that is the client's credential.

```go
store, err := sessions.NewFileStore("./sessions")
```

- It creates the directory with mode `0700`, and records get mode `0600`. Writes are atomic.
- IDs are validated before any path is built.
- With `Base64Encoder`, records on disk are neither encrypted nor authenticated. Use `AESGCMEncoder` if the storage environment isn't trusted.
- Each record file's modification time is set to the session's expiry. Expired records stay on disk until you call `store.Cleanup(ctx)` on a schedule; it removes exactly the records whose expiry has passed.
- It is safe for concurrent use within one process. Several processes sharing one directory get atomic writes, but a concurrent update may bring back a record another process just deleted.

### Custom components

Implement `Transport`, `Store`, or `Encoder`. The interfaces are small, and their doc comments define the contracts:

- **`Transport`:** `Read` returns `ErrNoCredential` only when the credential is absent, and an error matching `ErrInvalidSession` when it is malformed or ambiguous. `Write` and `Clear` only work before the response is committed.
- **`Store`:** records are opaque bytes. `Create` and `Update` receive the record's expiry in `StoreParams`, which a database store can use for a TTL, a cleanup job, or a `WHERE expires_at > now()` filter; the manager still checks expiry on every load. `Load` returns `ErrSessionNotFound` for a missing record, `Update` never creates one, and `Delete` succeeds when the record is already gone. A credential the store cannot interpret returns `ErrInvalidSession` and touches nothing. Report operational failures with a built-in category, never with the session kinds.
- **`Encoder`:** it must be safe for concurrent use and must not change or keep its input. `Decode` returns `ErrInvalidEncoding` for malformed or unauthenticated data and never returns partial output. Implement `RefreshDecoder` to ask for records to be re-encoded, as `RotatingEncoder` does.

A store that hands the record to the client must be paired with an authenticating encoder.

## Manager options

```go
manager, err := sessions.NewManager[SessionData](transport, encoder, store,
	sessions.WithLifetime(7*24*time.Hour), // absolute lifetime; default 30 days
	sessions.WithMaxRecordSize(64<<10),    // encoded record; default 64 KiB
	sessions.WithMaxPayloadSize(64<<10),   // serialized session; default 64 KiB
)
```

Session values are serialized as JSON. Unknown fields are ignored when loading, so removing a field from `T` doesn't invalidate existing sessions.

## Configuration examples

```go
// A. Browser cookie with an opaque ID; data on the server. No key needed.
store, err := sessions.NewFileStore("./sessions")
manager, err := sessions.NewManager[SessionData](cookieTransport, sessions.NewBase64Encoder(), store)

// B. Stateless, signed browser cookie. Clients can read, but not change, their session.
encoder, err := sessions.NewHMACEncoder(signingKey)
manager, err := sessions.NewManager[SessionData](cookieTransport, encoder, sessions.NewCookieStore())

// C. CLI or API client with a stable bearer ID.
bearer, err := sessions.NewBearerTransport(sessions.BearerTransportTokenHeader("App-Token"))
manager, err := sessions.NewManager[SessionData](bearer, sessions.NewBase64Encoder(), store)

// D. Data on the server, encrypted at rest.
encoder, err := sessions.NewAESGCMEncoder(encryptionKey)
manager, err := sessions.NewManager[SessionData](cookieTransport, encoder, store)
```

(Check every `err`. Runnable versions are in the [package examples](https://pkg.go.dev/github.com/stackus/sessions#pkg-examples).)

### Insecure combinations

`NewManager` does not check whether a combination is secure. Do not use these:

| Combination | Problem |
| --- | --- |
| `CookieStore` + `Base64Encoder` | **The client can read and forge its own session**, for example by changing its user ID. Never use it. |
| `CookieStore` + `HMACEncoder` | Safe from forgery, but **the client can read every value**. Don't put secrets in the session. |
| `FileStore` + `Base64Encoder` | Anyone who can read or write the session directory can read or change sessions. |
| `RotatingEncoder` with a `Base64Encoder` as a previous encoder | Accepts unauthenticated data. |

## Protecting routes

`RequireSession`, `RequireSessionState`, and `GuestOnly` check whether a session exists. They don't decide what it grants.

```go
toLogin := http.RedirectHandler("/login", http.StatusSeeOther)
isAdmin := func(s *sessions.Session[SessionData]) bool { return s.Values().Role == "admin" }

mux.Handle("/account", sessions.RequireSession(manager, toLogin)(accountHandler))
mux.Handle("/admin", sessions.RequireSessionState(manager, isAdmin, toLogin)(adminHandler))
mux.Handle("/login", sessions.GuestOnly(manager, http.RedirectHandler("/account", http.StatusSeeOther))(loginHandler))
```

- `onFailure` runs only when there is no usable session. An operational failure, such as an unreachable store, gets an error response instead and is never treated as "logged out".
- The helpers must run inside `manager.Middleware()`.
- `onFailure` can call `manager.Delete(w, r)` to clear a rejected credential.

## Warnings

> **Base64 is not security.** Never trust a client-controlled stateless session record that has only been base64-encoded. Signed cookies remain client-readable; use authenticated encryption if confidentiality is required.

> **Stateless deletion is not revocation.** Clearing a cookie or asking a CLI to delete a token does not invalidate a previously copied stateless credential. Choose a revocable server-side store when individual session revocation is required.

> **Bearer credentials are secrets.** Use TLS outside local development; secure local CLI token storage; no credentials in logs, URLs, analytics, or traces. A bearer response header is an application protocol, not a standard client credential-storage mechanism.

> **Session creation is not application login.** Authentication, authorization, deciding which values to place in sessions, and CSRF protection are application responsibilities. Rotate the credential when an anonymous session becomes a privileged one: `manager.Load`, then `manager.New`, then `Save` on the new session.

> **`Values()` is not deeply immutable.** Use `Set` and `Update`; avoid mutating maps, slices, or pointers obtained from `Values()`, or retaining the pointer passed to `Update`.

> **`Save` is a one-time commit.** Make all changes before calling `Session.Save`; later changes return `ErrSessionCommitted`.

> **HTTP response timing matters.** Save or clear credentials before anything is written to the response. The library cannot always detect a response that has already been sent.

> **Persistence is not a distributed transaction.** Storing a record and delivering its credential cannot be committed together. If issuing a new credential fails, `Save` deletes the new record on a best-effort basis. If deleting a replaced session's record fails, the old record remains until it expires. If a record cannot be deleted, `Delete` leaves the client's credential in place and returns the error. Concurrent requests for the same session are last-write-wins.

> **Custom components carry their own contracts.** The manager does not judge whether a combination is secure.

## Not included

- Authentication, authorization, and CSRF protection.
- Automatic saving middleware (explicit `Save` only).
- Automatic sliding expiration; a session's lifetime is only extended by an explicit `Extend`.
- Revoking individual stateless (`CookieStore`) sessions.
- Atomic credential replacement across arbitrary stores and HTTP.
- Client-side token storage for CLI applications.
- Pluggable serialization (values are JSON).

## Genesis

This project was created while the original gorilla repos were being archived and their future was unknown.
During that time I grabbed both [gorilla/sessions](https://github.com/gorilla/sessions) and [gorilla/securecookie](https://github.com/gorilla/securecookie)
and mashed them together into a new codebase.

Version 0.5 is a ground-up redesign with an explicit session lifecycle and interchangeable transports, stores, and encoders.

## License

This project is licensed under the BSD 3-Clause License — see the [LICENSE](LICENSE) file for details.

Gorilla/Sessions and Gorilla/SecureCookie licenses are included.
