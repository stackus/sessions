package sessions

import (
	"github.com/stackus/errors"
)

// RefreshDecoder is an optional Encoder capability. DecodeWithRefresh decodes
// like Decode and also reports whether the data should be re-encoded, for
// example because it was produced with a retired key.
//
// When the manager's encoder implements RefreshDecoder and reports refresh,
// the loaded session is re-encoded on its next Session.Save without its values
// being marked dirty.
type RefreshDecoder interface {
	DecodeWithRefresh(data []byte) (decoded []byte, refresh bool, err error)
}

// RotatingEncoder supports key rotation. It encodes with the current encoder
// and decodes with the current encoder first, then each previous encoder in
// order.
//
// Decoding moves on to the next encoder only when an encoder rejects the data
// with ErrInvalidEncoding; any other error is returned immediately. Encoding
// never falls back to a previous encoder.
//
// A RotatingEncoder is only as strong as the weakest encoder it accepts: a
// previous Base64Encoder, for example, lets unauthenticated data decode.
type RotatingEncoder struct {
	encoders []Encoder // encoders[0] is the current encoder
}

var (
	_ Encoder        = (*RotatingEncoder)(nil)
	_ RefreshDecoder = (*RotatingEncoder)(nil)
)

// NewRotatingEncoder returns a RotatingEncoder that encodes with current and
// also accepts data produced by any of previous, tried in the order given.
func NewRotatingEncoder(current Encoder, previous ...Encoder) (*RotatingEncoder, error) {
	encoders := make([]Encoder, 0, 1+len(previous))
	encoders = append(encoders, current)
	encoders = append(encoders, previous...)

	for i, enc := range encoders {
		if isNil(enc) {
			if i == 0 {
				return nil, errors.ErrInvalidArgument.Msg("rotating encoder: current encoder is nil")
			}
			return nil, errors.ErrInvalidArgument.Msgf("rotating encoder: previous encoder %d is nil", i-1)
		}
	}

	return &RotatingEncoder{encoders: encoders}, nil
}

// Encode encodes data with the current encoder.
func (r *RotatingEncoder) Encode(data []byte) ([]byte, error) {
	return r.encoders[0].Encode(data)
}

// Decode decodes data with the first encoder that accepts it.
func (r *RotatingEncoder) Decode(data []byte) ([]byte, error) {
	decoded, _, err := r.DecodeWithRefresh(data)
	return decoded, err
}

// DecodeWithRefresh decodes data with the first encoder that accepts it.
// refresh is true when a previous encoder accepted the data, or when the
// accepting encoder itself reports a refresh.
func (r *RotatingEncoder) DecodeWithRefresh(data []byte) ([]byte, bool, error) {
	var rejections []error

	for i, enc := range r.encoders {
		decoded, refresh, err := decodeWithRefresh(enc, data)
		if err == nil {
			return decoded, refresh || i > 0, nil
		}

		if !errors.Is(err, ErrInvalidEncoding) {
			return nil, false, err
		}

		rejections = append(rejections, err)
	}

	return nil, false, ErrInvalidEncoding.Wrap(errors.Join(rejections...), "rotating: no encoder accepted the data")
}

// decodeWithRefresh decodes with enc, using its RefreshDecoder capability when
// it has one.
func decodeWithRefresh(enc Encoder, data []byte) ([]byte, bool, error) {
	if rd, ok := enc.(RefreshDecoder); ok {
		return rd.DecodeWithRefresh(data)
	}

	decoded, err := enc.Decode(data)

	return decoded, false, err
}
