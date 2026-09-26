package sessions

// Encoder is a reversible byte-to-byte transformation that the manager applies
// to the complete serialized session record before it is handed to a Store,
// and reverses after the record is loaded.
//
// What an Encoder guarantees depends on the implementation: Base64Encoder only
// changes the representation, HMACEncoder adds authenticity and integrity but
// leaves the data readable, and AESGCMEncoder adds confidentiality as well.
//
// Implementations must:
//   - be safe for concurrent calls;
//   - never mutate their input or return a slice that aliases it;
//   - fail closed in Decode: malformed or unauthenticated input returns an
//     error matching ErrInvalidEncoding and no data.
//
// Any other error means an operational or configuration failure, such as a
// failing random source, and should be classified with a built-in category
// such as errors.ErrInternal. The manager reports ErrInvalidEncoding as an
// invalid session and every other error as an operational failure.
type Encoder interface {
	Encode(data []byte) ([]byte, error)
	Decode(data []byte) ([]byte, error)
}

// EncoderOption configures an encoder that accepts options, such as
// HMACEncoder and AESGCMEncoder.
type EncoderOption func(*encoderConfig)

type encoderConfig struct {
	label []byte
}

// WithEncoderLabel binds encoded data to label. The label is authenticated but
// not stored, so data encoded under one label fails to decode under a
// different label or no label. Use distinct labels to keep managers that share
// a key from accepting each other's records. By default, there is no label.
func WithEncoderLabel(label string) EncoderOption {
	return func(c *encoderConfig) {
		c.label = []byte(label)
	}
}

func newEncoderConfig(opts []EncoderOption) encoderConfig {
	var c encoderConfig
	for _, opt := range opts {
		opt(&c)
	}
	return c
}
