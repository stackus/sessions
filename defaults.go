package sessions

import (
	"crypto/sha256"
	"net/http"
)

// Cookie Defaults
var DefaultMaxAge = 86400 * 30 // 30 days

// Codec Defaults
var DefaultHashFn = sha256.New
var DefaultMaxLength = 4096
var DefaultSerializer Serializer = JsonSerializer{}

// Session Defaults
var DefaultPath = "/"
var DefaultDomain = ""
var DefaultSecure = false
var DefaultHttpOnly = true
var DefaultPartitioned = false
var DefaultSameSite = http.SameSiteLaxMode
