# Sessions

A type-safe, secure cookie manager for Go. Support for custom storage and encryption backends.

[![Go Reference](https://pkg.go.dev/badge/github.com/stackus/sessions.svg)](https://pkg.go.dev/github.com/stackus/sessions)
[![Go Report Card](https://goreportcard.com/badge/github.com/stackus/sessions)](https://goreportcard.com/report/github.com/stackus/sessions)
[![Coverage Status](https://coveralls.io/repos/stackus/sessions/badge.png)](https://coveralls.io/r/stackus/sessions)
![Test Status](https://github.com/stackus/sessions/actions/workflows/test.yaml/badge.svg)

## Features
- Type-safe session data: the session data is stored in a type that you define.
- Simple API: use it as an easy way to set signed (and optionally
  encrypted) cookies.
- Built-in backends to store sessions in cookies or the filesystem.
- Flash messages: session values that last until read.
- Convenient way to switch session persistency (aka "remember me") and set
  other attributes.
- Mechanism to rotate authentication and encryption keys.
- Multiple sessions per request, even using different backends.
- Interfaces and infrastructure for custom session backends: sessions from
  different stores can be retrieved and batch-saved using a common API.

## Requirements
- Go 1.23+

## Genesis
This project was created while the original gorilla repos were being archived and their future was unknown.
During that time I grabbed both [gorilla/sessions](https://github.com/gorilla/sessions) and [gorilla/securecookie](https://github.com/gorilla/securecookie)
and mashed them together into a new codebase.
I made changes here and there and eventually ended up with a new external API with a lot of the original code still intact.

Functionally, a lot of what this project does is the same as the original gorilla code.
The biggest changes are the changed API of the library, type-safe session data, and the two projects being merged into one.

## Example Usage

```go
package main

import (
	"github.com/stackus/sessions"
)

// create a type to hold the session data
type SessionData struct {
	UserID  int
	Scopes  []string
	IsAdmin bool
}

const myHashKey = "it's-a-secret-to-everybody."

func main() {
	// create a store; the CookieStore will save the session data in a cookie
	store := sessions.NewCookieStore()
	
	// create a Codec to encode and decode the session data; Codecs have a lot 
	// of options such as changing the Serializer, adding encryption for extra 
	// security, etc. These options can be passed in as variadic arguments
	codec := sessions.NewCodec(myHashKey)
	
	// create the cookie options that will dictate how the cookie is saved by the browsers
	cookieOptions := sessions.NewCookieOptions()
	cookieOptions.MaxAge = 3600 // 1 hour
	
	// create a new session manager for SessionData and with the cookieOptions, store, and 
	// one or more codecs
	sessionManager := sessions.NewSessionManager[SessionData](cookieOptions, store, codec)
	
	// later in an HTTP handler get the session for the request; if it doesn't exist, a 
	// new session is initialized and can be checked with the `IsNew` value
	session, _ := sessionManager.Get(r, "my-session")
	
	// access the session data directly and with type safety
	session.Values.UserID = 1
	session.Values.Scopes = []string{"read", "write"}
	
	// save the session data
	_ = session.Save(w, r)
}
```

## Stores
Two stores are available out of the box: `CookieStore` and `FileSystemStore`.

### CookieStore
```go
store := sessions.NewCookieStore()
```

The `CookieStore`  saves the session data in a cookie.
This is particularly useful when you want horizontal scalability
and don't want to store the session data on the server or add additional infrastructure 
to manage the session data.
I highly recommend using encryption in the Codecs when using the `CookieStore`.

### FileSystemStore
```go
store := sessions.NewFileSystemStore(rootPathForSessions, maxFileSize)
```

The `FileSystemStore` saves the session data in a file on the server's filesystem.
If you are using a single server and do not want to store the session data in a cookie,
then this might be a good option for you.

### Additional Stores
Additional stores can be created by implementing the `Store` interface.
```go
type Store interface {
	Get(ctx context.Context, proxy *SessionProxy, cookieValue string) error
	New(ctx context.Context, proxy *SessionProxy) error
	Save(ctx context.Context, proxy *SessionProxy) error
}
```

## Codecs
```go
codec := sessions.NewCodec(hashKey, options...)
```
The `Codec` is responsible for encoding and decoding the session data as well as optionally 
encrypting and decrypting the data.

All Codecs require a HashKey which will be used to authenticate the session data using [HMAC](https://en.wikipedia.org/wiki/HMAC).
Additional options can be passed in as variadic arguments to the `NewCodec` function to 
change the default behavior of the Codec.

### NewCodec Options
- `WithMaxAge`: sets the maximum age of the session cookie, defaults to 30 days
- `WithMinAge`: sets the minimum age of the session cookie, defaults to 0
- `WithMaxLength`: sets the maximum length of the encoded session cookie value, defaults to 4096
- `WithHashFn`: sets the hash function used by the codec, defaults to sha256.New
- `WithBlockKey`: sets the block key used by the codec; aes.NewCipher is used to create the block cipher
- `WithBlock`: sets the block cipher used by the codec, defaults to aes.NewCipher
- `WithSerializer`: sets the serializer used by the codec, defaults to sessions.JsonSerializer

## SessionManager
```go
sessionManager := sessions.NewSessionManager[SessionData](cookieOptions, store, codec)
```

The `SessionManager` is responsible for managing the session data for a specific type.
The `SessionManager` requires a `CookieOptions`, a `Store`, and one or more `Codecs`.

### Multiple Types Of Sessions
You will need to configure a different `SessionManager` for each type of session data you want to manage.
A common pattern is to create a cookie for "Access," and then one for "Refresh" tokens.

```go
accessManager := sessions.NewSessionManager[AccessData](cookieOptions, store, codec)
refreshManager := sessions.NewSessionManager[RefreshData](cookieOptions, store, codec)
```
You can reuse the same `CookieOptions`, `Store`,
and `Codec` for each `SessionManager` if you'd like, 
but you can also configure them differently.


### CookieOptions
```go
cookieOptions := sessions.NewCookieOptions()
```
The `CookieOptions` dictate how the session cookie is saved by the browser.
The `CookieOptions` have the following fields:
- `Path`: the path of the cookie, defaults to "/"
- `Domain`: the domain of the cookie, defaults to ""
- `MaxAge`: the maximum age of the cookie in seconds, defaults to 30 days
- `Secure`: whether the cookie should only be sent over HTTPS, defaults to false
- `HttpOnly`: whether the cookie should be accessible only through HTTP, defaults to true
- `Partitioned`: whether the cookie should be partitioned, defaults to false
- `SameSite`: the SameSite attribute of the cookie, defaults to SameSiteLaxMode

> Paritioned is a relatively new attribute that is not yet widely supported by browsers and will require Go 1.23+ to use.
> 
> For more information: https://developer.mozilla.org/en-US/docs/Web/Privacy/Privacy_sandbox/Partitioned_cookies

### Getting a Session
```go
session, _ := sessionManager.Get(r, "__Host-my-session")
```
The `Get` function will return a session of type `*Session[T]`, where `T` is the type
provided to the `SessionManager`, from the given request and the matching cookie name.
If the session does not exist, a new session will be initialized by the `Store` that
is associated with the `SessionManager`.

### Key Rotation
Key rotation is a critical part of securing your session data.
By providing multiple Codecs to the `SessionManager`, you can rotate the keys used to
encode and decode the session data.

```go
codec1 := sessions.NewCodec(hashKey1)
codec2 := sessions.NewCodec(hashKey2)
sessionManager := sessions.NewSessionManager[SessionData](cookieOptions, store, codec1, codec2)
```
This way you can still decode session data encoded with the old key while encoding new 
session data with the new key.
The `BlockKey` and `Serializer` can also be changed between Codecs to provide additional
security and flexibility.

## Session
The `Session` type is a wrapper around the session data and provides a type-safe way to
access and save the session data.
You can access the session data directly through the `Values` field.

```go
type SessionData struct {
	UserID  int
	Scopes  []string
	IsAdmin bool
}

// Values is a SessionData type
session.Values.UserID = 1
session.Values.Scopes = []string{"read", "write"}
```

### Saving a Session
```go
err = session.Save(w, r)
```
The `Save` function will save the session data to the `Store` and set the session cookie
in the response writer.
This will write the session data to the `Store` and set the session cookie in the response
even if the session data has not changed.

### Deleting a Session
```go
err = session.Delete(w, r) // cookie will be set to expire immediately
// OR
session.Expire() // do this anywhere you do not have access to the response writer
session.Save(w, r) // cookie will be deleted
```

### Session Cookie and Store Persistence
The session will inherit the `CookieOptions` from the `SessionManager`, but there may be times
when you want to change whether the session cookie is persistent or not.
For example, if you have added a "Remember Me" feature to your application.

Two methods exist on the session to help with overriding the `MaxAge` set in the `CookieOptions` for the `SessionManager`:
- `Persist(maxAge int)`: alters the session instance to set the session cookie to be persisted for the provided `maxAge` in seconds
- `DoNotPersist()`: alters the session instance to set the session cookie to be deleted when the browser is closed

```go
if rememberMe {
	session.Persist(86400) // 1 day
} else {
	session.DoNotPersist()
}
```

### Saving all Sessions
```go
err = sessions.Save(w, r)
```
The `Save` function will save all sessions in the request context.
This is useful when you have multiple sessions in a single request.
All sessions will be saved even if the session data has not changed.

## Information for Store Implementors
Implementing a new `Store` is relatively simple.
The `Store` interface has three methods: `Get`, `New`, and `Save`.

```go
type Store interface {
	Get(ctx context.Context, proxy *SessionProxy, cookieValue string) error
	New(ctx context.Context, proxy *SessionProxy) error
	Save(ctx context.Context, proxy *SessionProxy) error
}
```

### Get
The `Get` method is responsible for retrieving the session data from the store.
Unlike in the original gorilla/sessions, the `Get` method is only called after 
the session data has been loaded from the cookie.
The cookie value is passed in exactly as it was received from the request.
You should `Decode` the cookie value into the `proxy.ID` or `proxy.Values` fields.

```go
func (s *MyStore) Get(ctx context.Context, proxy *SessionProxy, cookieValue string) error {
	// decode the cookie value into the proxy.ID or proxy.Values
	err := s.Codec.Decode([]byte(cookieValue), &proxy.ID)
	// now you've got the ID of the record or row that your store can then use to get the session data
}

```

### New
The `New` method is responsible for initializing a new session.
This method is called when a cookie is not found in the request.

### Save
The `Save` method is responsible for saving the session data to the store and setting
the session cookie in the response writer.

### SessionProxy
The `SessionProxy` is a helper type that provides access to the session data and session lifecycle methods.

Fields:
- `ID string`: The store should use this to keep track of the session data record or row.
- `Values any`: This will be what holds or will hold the session data. It is recommended to only interact with this field with either the `Encode` or `Decode` methods.
- `IsNew bool`: This will be true if the session is new, meaning it was created during this request and the stores `New` method was called.

Methods:
- `Decode(data []byte, dst any) error`: decodes the session data into the provided destination such as the `proxy.ID` or `proxy.Values`. The Codecs that were provided to the `SessionManager` will be used during the decoding process.
- `Encode(src any) ([]byte, error)`: encodes the provided source such as the `proxy.ID` or `proxy.Values` into a byte slice. The Codecs that were provided to the `SessionManager` will be used during the encoding process.
- `Save(value string) error`: write the session cookie to the response writer with the provided value as the cookie value. The `MaxAge` in the cookie options will be used to determine if the cookie should be deleted or not. It is recommended to call this method or `Delete` from inside the stores `Save` method.
- `Delete() error`: delete the session cookie from the response writer.
- `IsExpired() bool`: returns true if the session cookie is expired.
- `MaxAge() int`: returns the maximum age of the session cookie.

## License
This project is licensed under the BSD 3-Clause License — see the [LICENSE](LICENSE) file for details.

Gorilla/Sessions and Gorilla/SecureCookie licenses are included.
