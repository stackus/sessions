# Migrating from v0.4 to v0.5

Version 0.5 is a ground-up redesign. The package path is unchanged, but almost every API has changed, and **sessions created by v0.4 cannot be read by v0.5**.

This guide maps the v0.4.1 API to its replacement and explains the behavior changes that matter when upgrading.

## Before you start

- **Go 1.26 or later** is required.
- **Existing sessions end.** A v0.4 cookie fails to decode, and `Load` reports it as `ErrInvalidSession`, which `IsNoSession` treats as "no session". Users sign in again once. Clear the old cookie with `manager.Delete(w, r)`, or let the next saved session replace it (see [Stale cookies](#stale-cookies)).
- **Behavior changes that can break silently:**
  - Sessions are no longer created on `Get`.
  - Nothing is saved unless you call `Save`.
  - Cookies are now `Secure` by default.
  - Store errors are no longer hidden.

## At a glance

```go
// v0.4
cookieOptions := sessions.NewCookieOptions("session")
codec := sessions.NewCodec(hashKey)
manager := sessions.NewSessionManager[SessionData](cookieOptions, sessions.NewCookieStore(), []sessions.Codec{codec})

session, _ := manager.Get(r)          // always returns a session, new or loaded
if session.IsNew { /* ... */ }
session.Values.UserID = 1             // direct field access
_ = session.Save(w, r)
```

```go
// v0.5
transport, err := sessions.NewCookieTransport("session")
// handle err
encoder, err := sessions.NewHMACEncoder(hashKey) // key must be at least 32 bytes
// handle err
manager, err := sessions.NewManager[SessionData](transport, encoder, sessions.NewCookieStore())
// handle err

mux.Handle("/", manager.Middleware()(handler)) // required on every route that uses sessions

sess, err := manager.LoadOrNew(r)     // existing session, or a new in-memory one
// handle err (always operational)
if sess.IsNew() { /* ... */ }
err = sess.Update(func(v *SessionData) { v.UserID = 1 })
err = sess.Save(w)                    // before writing the response
```

## API mapping

### Manager

| v0.4.1 | v0.5 |
| --- | --- |
| `NewSessionManager[T](cookieOptions, store, codecs, opts...) SessionManager[T]` | `NewManager[T](transport, encoder, store, opts...) (*Manager[T], error)` |
| `SessionManager[T]` interface | `*Manager[T]` (a concrete type) |
| `manager.Get(r)`, which created a session when none existed | `manager.LoadOrNew(r)`, which returns the existing session or a new in-memory one; or `manager.Load(r)`, which returns an existing session or an error for which `IsNoSession` is true, plus `manager.New(r)` to create one |
| `manager.Save(w, r, session)` | `sess.Save(w)` |
| `WithGracefulDecodeFailure()` | Check `sessions.IsNoSession(err)` and call `manager.New(r)` yourself. Store failures are no longer hidden. |
| No middleware required | `manager.Middleware()` is required; without it, calls return `ErrNoScope` |
| `DefaultMaxAge` and other `Default*` variables | `WithLifetime`, `WithMaxRecordSize`, `WithMaxPayloadSize`, and component options |

### Session

| v0.4.1 | v0.5 |
| --- | --- |
| `session.Values` (field) | `sess.Values()` (a shallow copy), `sess.Set(v)`, `sess.Update(func(*T))` |
| `session.IsNew` | `sess.IsNew()`, true until the session is first persisted. |
| `session.Save(w, r)` | `sess.Save(w)`: commits once, saves only if something changed, and must run before the response is written |
| `session.Delete(w, r)` / `session.Expire()` | `sess.Delete(w)` or `manager.Delete(w, r)`, which also clears credentials that cannot be decoded |
| `session.Persist(maxAge)` / `session.DoNotPersist()` | Removed. The session lifetime is `WithLifetime`, and a persistent cookie expires with the session. `CookieTransportPersistent(false)` makes a browser-session cookie. |
| Change detection by hashing the values | Explicit: `Set` and `Update` mark the session as changed |
| `sessions.Save(w, r)` (save every session) | Call `Save` on each session you changed. There is no automatic saving. |
| `SaveSessions` middleware | Removed. Call `sess.Save(w)` in the handler before writing the response. |
| `StoreInContext` / `FromContext` | Removed. Call `manager.Load(r)`; it is cached per request. |
| `Init()` method on `T` | Removed. `New(r)` creates zero-valued `T`; pass initial values with `New(r, v)`. |

### Cookies and transports

| v0.4.1 | v0.5 |
| --- | --- |
| `NewCookieOptions(name)` and its fields | `NewCookieTransport(name, opts...) (*CookieTransport, error)` |
| `Path`, `Domain`, `HttpOnly`, `SameSite`, `Partitioned` | `CookieTransportPath`, `CookieTransportDomain`, `CookieTransportHTTPOnly`, `CookieTransportSameSite`, `CookieTransportPartitioned` |
| `Secure` (default **false**) | `CookieTransportSecure` (default **true**). Pass `CookieTransportSecure(false)` for local HTTP development. |
| `MaxAge` in seconds | The manager's `WithLifetime`; the cookie follows the session's expiry |
| Codec `WithMaxLength` (cookie length) | `CookieTransportMaxCredentialSize` (default 4096) |
| none | `NewBearerTransport` for CLI and API clients |

### Codecs and encoders

| v0.4.1 | v0.5 |
| --- | --- |
| `NewCodec(hashKey, opts...)` | `NewHMACEncoder(key, opts...)`, which authenticates but does **not** encrypt |
| `WithBlockKey(key)` / `WithBlock(block)` (AES-CTR plus HMAC) | `NewAESGCMEncoder(key)`, which authenticates and encrypts |
| Several codecs for key rotation | `NewRotatingEncoder(current, previous...)`. Old-key sessions are re-encoded on their next `Save`. |
| Cookie name bound into the MAC | `WithEncoderLabel("name")` |
| `WithMaxAge` / `WithMinAge` (timestamp in the codec) | The manager's `WithLifetime`. Expiry is stored in the authenticated record and checked on every load. There is no minimum age. |
| `WithHashFn` | Removed (fixed HMAC-SHA256) |
| `WithSerializer`, `JsonSerializer`, `GobSerializer` | Removed. Values are always JSON. |
| No unauthenticated codec | `NewBase64Encoder()`, only for server-side stores in a trusted environment |

v0.4 required a hash key for every codec. v0.5 lets you choose, which means **you can build an insecure configuration**. See [Insecure combinations](README.md#insecure-combinations). In particular, never pair `CookieStore` with `Base64Encoder`.

### Stores

| v0.4.1 | v0.5 |
| --- | --- |
| `NewCookieStore()` | `NewCookieStore()`, which now requires an authenticating encoder |
| `NewFileSystemStore(root, maxFileSize)` | `NewFileStore(dir) (*FileStore, error)`, plus `Cleanup(ctx)` for expired records. The size limit is the manager's `WithMaxRecordSize`. |
| `Store` interface: `Get`/`New`/`Save` with a `*SessionProxy` | `Store` interface: `Load`/`Create`/`Update`/`Delete` over opaque bytes and a credential. HTTP and encoding are no longer the store's job. |
| `SessionProxy` (`Encode`, `Decode`, `Save`, `Delete`, `IsExpired`, `MaxAge`) | Removed. The manager encodes records, and transports handle HTTP. |

To port a custom store, store and return the bytes you are given, keyed by a credential you generate. Return `ErrSessionNotFound` for missing records and `ErrInvalidSession` for credentials you cannot interpret. See the `Store` documentation.

### Route helpers

| v0.4.1 | v0.5 |
| --- | --- |
| `RequireSession(mgr SessionManager[T], onFailure)` | `RequireSession(m *Manager[T], onFailure)` |
| `RequireSessionState(mgr, check, onFailure)` | `RequireSessionState(m, check, onFailure)` |
| `GuestOnly(mgr, onFailure)` | `GuestOnly(m, onFailure)` |

The names are the same, but the behavior changed. v0.4 treated **every** error as "no session", so a store outage looked like a logged-out user. v0.5 calls `onFailure` only for unavailable sessions and answers operational failures with an error response. The helpers now need `manager.Middleware()`.

### Flash messages

`Flash` has been removed. If you relied on it, keep your own map in `T` and change it through `Update`. Reading a flash message changes the session, so it must be saved.

### Errors

Errors are now [`github.com/stackus/errors`](https://github.com/stackus/errors) kinds. Each carries an HTTP status and a message that is safe to show to clients.

| v0.4.1 | v0.5 |
| --- | --- |
| `ErrHMACIsInvalid`, `ErrTimestampIsInvalid`, `ErrDecryptionFailed` (on load) | `ErrInvalidSession` (unavailable), wrapping `ErrInvalidEncoding` for failed authentication or decryption |
| `ErrSerializeFailed`, `ErrDeserializeFailed` | Operational `errors.ErrInternal` errors. A record that authenticates but whose values no longer fit `T` is not reported as unavailable. |
| `ErrTimestampIsExpired` | `ErrSessionExpired` |
| `ErrTimestampIsTooNew` | Removed (no minimum age) |
| `ErrSessionNotFound` (no session in the request context) | Removed. `ErrSessionNotFound` now means "the store has no record for this credential". |
| `ErrHashKeyNotSet`, `ErrCreatingBlockCipher`, `ErrNoCodecs` | Constructor errors: `errors.ErrInvalidArgument` from `NewHMACEncoder`, `NewAESGCMEncoder`, `NewManager` |
| `ErrEncodedLengthTooLong` | `ErrInvalidSession` when loading, and an operational error when saving |
| `ErrInvalidSessionType`, `ErrNoResponseWriter` | Removed |
| none | `ErrNoSession`, `ErrSessionDeleted`, `ErrNoScope`, `ErrSessionCommitted`, `ErrSessionReplaced`, `ErrNoCredential`, and `IsNoSession` |

## Behavior changes

### No session is created until you ask

`Get` used to return a new session whenever there was none, and `Save` issued a cookie for it. Now `Load` returns `ErrNoSession`, and a session exists only after you call `New`. A `New` session that you never change is not saved, even if you call `Save`.

### Save is explicit and one-time

Nothing is saved automatically, and there is no `SaveSessions` middleware. Call `sess.Save(w)` after your changes and **before writing the response**. After it succeeds, further changes return `ErrSessionCommitted`. Unchanged sessions are not rewritten, and a `FileStore` session's cookie is not reissued on every request.

### Values change through methods

`Values()` returns a copy. Assigning to it doesn't change the session. Maps, slices, and pointers inside it are shared, but changing them isn't tracked, so use `Set` or `Update`.

### Lifetime is absolute

In v0.4 the timestamp was rewritten on every save. In v0.5 the lifetime counts from when the session was first saved, and it is not extended by later saves or reads. Call `sess.Extend()` before `Save` to restart it; `sess.ExpiresAt()` tells you how much is left.

### Stale cookies

```go
sess, err := manager.Load(r)
switch {
case errors.Is(err, sessions.ErrInvalidSession):
	_ = manager.Delete(w, r) // clear the undecodable cookie
	// continue as anonymous
case sessions.IsNoSession(err):
	// no session: continue as anonymous
case err != nil:
	http.Error(w, errors.PublicMessage(err), errors.HTTPCode(err))
	return
}
```

`Delete` never decodes the credential, so it clears old v0.4 cookies and cookies signed with a retired key.

### Rotating credentials at login

To give a user a new credential when they sign in, call `Load`, then `New`, then `Save`. Saving the new session deletes the old record from a server-side store.

### Key rotation

1. Deploy with `NewRotatingEncoder(newKey, oldKey)`.
2. Sessions signed with the old key keep working and are re-encoded with the new key the next time they are saved.
3. Once the old sessions have expired, remove the old key.
