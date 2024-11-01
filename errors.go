package sessions

import (
	"github.com/stackus/errors"
)

var (
	ErrHashKeyNotSet        = errors.ErrInternalServerError.Msg("the hash key is not set for the codec")
	ErrEncodedLengthTooLong = errors.ErrOutOfRange.Msg("the encoded value is too long")
	ErrSerializeFailed      = errors.ErrInternalServerError.Msg("the value cannot be serialized")
	ErrDeserializeFailed    = errors.ErrInternalServerError.Msg("the value cannot be deserialized")
	ErrHMACIsInvalid        = errors.ErrBadRequest.Msg("the value cannot be validated")
	ErrTimestampIsInvalid   = errors.ErrBadRequest.Msg("the timestamp is invalid")
	ErrTimestampIsTooNew    = errors.ErrOutOfRange.Msg("the timestamp is too new")
	ErrTimestampIsExpired   = errors.ErrOutOfRange.Msg("the timestamp has expired")
	ErrCreatingBlockCipher  = errors.ErrInternalServerError.Msg("failed to create block cipher")
	ErrGeneratingIV         = errors.ErrInternalServerError.Msg("error generating the random iv")
	ErrDecryptionFailed     = errors.ErrInternalServerError.Msg("the value cannot be decrypted")
	ErrNoCodecs             = errors.ErrInternalServerError.Msg("no codecs were provided")
	ErrNoResponseWriter     = errors.ErrInternalServerError.Msg("no response writer was provided")
	ErrInvalidSessionType   = errors.ErrBadRequest.Msg("the session type is incorrect")
)
