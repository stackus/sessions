package sessions

import (
	"net/http"
)

type CookieOptions struct {
	Name        string
	Path        string
	Domain      string
	MaxAge      int
	Secure      bool
	HttpOnly    bool
	Partitioned bool
	SameSite    http.SameSite
}

// NewCookieOptions returns a new CookieOptions with default values.
//
// The default values are:
//   - Name: ""
//   - Path: "/"
//   - Domain: ""
//   - MaxAge: 86400 * 30
//   - Secure: false
//   - HttpOnly: true
//   - Partitioned: false
//   - SameSite: http.SameSiteLaxMode
func NewCookieOptions() CookieOptions {
	return CookieOptions{
		Name:        "",
		Path:        DefaultPath,
		Domain:      DefaultDomain,
		MaxAge:      DefaultMaxAge,
		Secure:      DefaultSecure,
		HttpOnly:    DefaultHttpOnly,
		Partitioned: DefaultPartitioned,
		SameSite:    DefaultSameSite,
	}
}
