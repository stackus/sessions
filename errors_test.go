package sessions

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
)

func TestIsNoSession(t *testing.T) {
	tests := map[string]struct {
		err  error
		want bool
	}{
		"nil":                   {err: nil, want: false},
		"no session":            {err: ErrNoSession, want: true},
		"invalid session":       {err: ErrInvalidSession, want: true},
		"expired":               {err: ErrSessionExpired, want: true},
		"not found":             {err: ErrSessionNotFound, want: true},
		"deleted":               {err: ErrSessionDeleted, want: true},
		"no scope":              {err: ErrNoScope, want: false},
		"committed":             {err: ErrSessionCommitted, want: false},
		"replaced":              {err: ErrSessionReplaced, want: false},
		"invalid encoding":      {err: ErrInvalidEncoding, want: false},
		"no credential":         {err: ErrNoCredential, want: false},
		"kind msg":              {err: ErrSessionExpired.Msg("expired at noon"), want: true},
		"kind wrap":             {err: ErrInvalidSession.Wrap(ErrInvalidEncoding.Msg("bad tag"), "decode"), want: true},
		"package wrap":          {err: errors.Wrap(ErrSessionNotFound, "load"), want: true},
		"fmt wrap":              {err: fmt.Errorf("load: %w", ErrNoSession), want: true},
		"join":                  {err: errors.Join(errors.New("other"), ErrSessionDeleted), want: true},
		"join operational only": {err: errors.Join(errors.New("a"), ErrNoScope), want: false},
		"bare category":         {err: errors.ErrUnauthenticated, want: false},
		"category msg":          {err: errors.ErrUnauthenticated.Msg("app login required"), want: false},
		"operational":           {err: errors.ErrInternal.Wrap(errors.New("disk"), "file store: read record"), want: false},
		"plain":                 {err: errors.New("boom"), want: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsNoSession(tc.err))
		})
	}
}

func TestErrorClassification(t *testing.T) {
	tests := map[string]struct {
		err        error
		typeCode   string
		httpCode   int
		publicText string
	}{
		"no session":       {ErrNoSession, "SESSION_NONE", http.StatusUnauthorized, "A session is required"},
		"invalid session":  {ErrInvalidSession, "SESSION_INVALID", http.StatusUnauthorized, "The session is invalid"},
		"expired":          {ErrSessionExpired, "SESSION_EXPIRED", http.StatusUnauthorized, "The session has expired"},
		"not found":        {ErrSessionNotFound, "SESSION_NOT_FOUND", http.StatusUnauthorized, "The session is invalid"},
		"deleted":          {ErrSessionDeleted, "SESSION_DELETED", http.StatusUnauthorized, "The session has ended"},
		"no scope":         {ErrNoScope, "SESSION_NO_SCOPE", http.StatusInternalServerError, "Internal Server Error"},
		"committed":        {ErrSessionCommitted, "SESSION_COMMITTED", http.StatusInternalServerError, "Internal Server Error"},
		"replaced":         {ErrSessionReplaced, "SESSION_REPLACED", http.StatusInternalServerError, "Internal Server Error"},
		"invalid encoding": {ErrInvalidEncoding, "SESSION_INVALID_ENCODING", http.StatusBadRequest, "Bad Request"},
		"no credential":    {ErrNoCredential, "SESSION_NO_CREDENTIAL", http.StatusUnauthorized, "Unauthorized"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// A wrapped kind must report the same classification as the bare kind.
			for _, err := range []error{tc.err, errors.Wrap(tc.err, "context")} {
				assert.Equal(t, tc.typeCode, errors.TypeCode(err))
				assert.Equal(t, tc.httpCode, errors.HTTPCode(err))
				assert.Equal(t, tc.publicText, errors.PublicMessage(err))
			}
		})
	}
}

func TestInvalidSessionWrappingEncoding(t *testing.T) {
	err := ErrInvalidSession.Wrap(ErrInvalidEncoding.Msg("bad tag"), "decode")

	assert.Equal(t, "SESSION_INVALID", errors.TypeCode(err))
	assert.Equal(t, http.StatusUnauthorized, errors.HTTPCode(err))
	assert.True(t, errors.Is(err, ErrInvalidSession))
	assert.True(t, errors.Is(err, ErrInvalidEncoding))
	assert.True(t, IsNoSession(err))
}
