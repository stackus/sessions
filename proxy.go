package sessions

import (
	"net/http"
	"time"

	"github.com/stackus/errors"
)

type SessionProxy struct {
	ID      string
	Values  any
	IsNew   bool
	req     *http.Request
	resp    http.ResponseWriter
	codecs  []Codec
	options *CookieOptions
}

// Decode will decode the data into the dst value.
//
// Codecs that have been configured for this session will be used.
//
// This should be used to read the session value from the request.
// Example:
//
//	err := proxy.Decode([]byte(cookieValue), proxy.Values)
//	if err != nil {
//		return err
//	}
//
// Useful destinations are the Values and ID fields of the SessionProxy.
func (sp *SessionProxy) Decode(data []byte, dst any) error {
	if len(sp.codecs) == 0 {
		return ErrNoCodecs
	}

	var errs []error
	for _, codec := range sp.codecs {
		err := codec.Decode(sp.options.Name, data, dst)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// Encode will encode the src value into a byte slice.
//
// Codecs that have been configured for this session will be used.
//
// This should be called before calling Save.
// Example:
//
//	encoded, err := proxy.Encode(proxy.Values)
//	if err != nil {
//		return err
//	}
//	return proxy.Save(string(encoded))
func (sp *SessionProxy) Encode(src any) ([]byte, error) {
	if len(sp.codecs) == 0 {
		return nil, ErrNoCodecs
	}

	var errs []error
	for _, codec := range sp.codecs {
		encoded, err := codec.Encode(sp.options.Name, src)
		if err == nil {
			return encoded, nil
		}
		errs = append(errs, err)
	}

	return nil, errors.Join(errs...)
}

// Save will write the session value into a cookie and to the response writer.
//
// The cookie will be deleted if the cookie is expired based on its MaxAge.
func (sp *SessionProxy) Save(value string) error {
	if sp.resp == nil {
		return ErrNoResponseWriter
	}

	cookie := &http.Cookie{
		Name:        sp.options.Name,
		Value:       value,
		Path:        sp.options.Path,
		Domain:      sp.options.Domain,
		MaxAge:      sp.options.MaxAge,
		Secure:      sp.options.Secure,
		HttpOnly:    sp.options.HttpOnly,
		Partitioned: sp.options.Partitioned,
		SameSite:    sp.options.SameSite,
	}

	switch {
	case sp.options.MaxAge > 0:
		// Set the expiration time for the cookie.
		cookie.Expires = time.Now().Add(time.Duration(sp.options.MaxAge) * time.Second)
	case sp.options.MaxAge < 0:
		// Set it to the past to expire now; clear the cookie value as well.
		cookie.Expires = time.Unix(1, 0).UTC()
		cookie.Value = ""
	default:
		// noop; cookie will expire when the browser is closed
	}

	http.SetCookie(sp.resp, cookie)
	return nil
}

// Delete will delete the session cookie regardless of its MaxAge.
func (sp *SessionProxy) Delete() error {
	if sp.resp == nil {
		return ErrNoResponseWriter
	}

	cookie := &http.Cookie{
		Name:        sp.options.Name,
		Value:       "",
		Path:        sp.options.Path,
		Domain:      sp.options.Domain,
		Expires:     time.Unix(1, 0),
		MaxAge:      -1,
		Secure:      sp.options.Secure,
		HttpOnly:    sp.options.HttpOnly,
		Partitioned: sp.options.Partitioned,
		SameSite:    sp.options.SameSite,
	}

	http.SetCookie(sp.resp, cookie)
	return nil
}

func (sp *SessionProxy) IsExpired() bool {
	return sp.options.MaxAge < 0
}

func (sp *SessionProxy) MaxAge() int {
	return sp.options.MaxAge
}
