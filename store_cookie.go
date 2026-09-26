package sessions

import (
	"context"
	"encoding/base64"
)

// CookieStore is a stateless store: the credential is the encoded record
// itself, represented as unpadded base64url text, and nothing is kept on the
// server.
//
// Because the client holds the whole record, CookieStore requires an encoder
// that authenticates it: HMACEncoder (the client can read but not change the
// values), AESGCMEncoder (the client can neither read nor change them), or a
// RotatingEncoder of those. Pairing CookieStore with Base64Encoder is insecure:
// the client can read and forge its own session. NewManager does not prevent
// this combination.
//
// Deleting or replacing a CookieStore session only clears the client's current
// credential. A copied credential remains valid until it expires or its key is
// retired; use a server-side store when sessions must be revocable.
type CookieStore struct{}

var _ Store = (*CookieStore)(nil)

// NewCookieStore returns a CookieStore.
func NewCookieStore() *CookieStore {
	return &CookieStore{}
}

// Load returns the record carried by credential. Decoding base64 is not
// authentication: the manager authenticates the returned bytes with its
// encoder. A credential that is not canonical unpadded base64url returns an
// error matching ErrInvalidSession.
func (*CookieStore) Load(_ context.Context, credential string, _ StoreParams) ([]byte, error) {
	data, err := base64.RawURLEncoding.Strict().DecodeString(credential)
	if err != nil {
		return nil, ErrInvalidSession.Wrap(err, "cookie store: decode credential")
	}

	return data, nil
}

// Create returns a credential that carries data. The expiry in params is not
// needed: it is carried inside the authenticated record.
func (*CookieStore) Create(_ context.Context, data []byte, _ StoreParams) (string, error) {
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Update returns a new credential that carries data. The credential changes
// whenever the record does.
func (*CookieStore) Update(_ context.Context, _ string, data []byte, _ StoreParams) (string, error) {
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// Delete does nothing: there is no server-side record. The manager clears the
// client's credential through the transport.
func (*CookieStore) Delete(context.Context, string) error {
	return nil
}
