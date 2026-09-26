package sessions

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/stackus/errors"
)

const (
	defaultLifetime       = 30 * 24 * time.Hour
	defaultMaxRecordSize  = 64 << 10
	defaultMaxPayloadSize = 64 << 10
)

const envelopeVersion = 1

// envelope is the serialized session record before encoding. The encoder is
// applied to the whole envelope, so the timestamps are authenticated together
// with the values.
type envelope struct {
	Version   int             `json:"v"`
	CreatedAt int64           `json:"c"` // Unix seconds
	ExpiresAt int64           `json:"e"` // Unix seconds
	Data      json.RawMessage `json:"d"` // JSON-serialized T
}

// envelopeMeta is the session metadata carried by an envelope.
type envelopeMeta struct {
	CreatedAt time.Time
	ExpiresAt time.Time
}

// marshalEnvelope serializes values into an envelope. The timestamps are
// stored with one-second precision. All failures are operational: the values
// cannot be serialized, the timestamps are incoherent, or the envelope is
// larger than maxPayload and so could never be loaded again.
func marshalEnvelope[T any](values T, meta envelopeMeta, maxPayload int) ([]byte, error) {
	created, expires := meta.CreatedAt.Unix(), meta.ExpiresAt.Unix()
	if created <= 0 || expires <= created {
		return nil, errors.ErrInternal.Msg("envelope: expiry must be after creation")
	}

	data, err := json.Marshal(values)
	if err != nil {
		return nil, errors.ErrInternal.Wrap(err, "serialize session values")
	}

	out, err := json.Marshal(envelope{
		Version:   envelopeVersion,
		CreatedAt: created,
		ExpiresAt: expires,
		Data:      data,
	})
	if err != nil {
		return nil, errors.ErrInternal.Wrap(err, "serialize session envelope")
	}

	if len(out) > maxPayload {
		return nil, errors.ErrInternal.Msgf("envelope: session of %d bytes exceeds the %d byte payload limit", len(out), maxPayload)
	}

	return out, nil
}

// unmarshalEnvelope validates a decoded envelope and deserializes its values.
//
// An oversized, malformed, or unknown-version envelope, or one with missing or
// incoherent timestamps, returns ErrInvalidSession. An envelope whose expiry
// is at or before now returns ErrSessionExpired. A failure to deserialize T
// after the envelope is accepted is operational: it indicates a schema or
// configuration mismatch, not a client fault. Every error returns the zero T.
func unmarshalEnvelope[T any](data []byte, now time.Time, maxPayload int) (T, envelopeMeta, error) {
	var zero T
	if len(data) > maxPayload {
		return zero, envelopeMeta{}, ErrInvalidSession.Msgf("envelope: %d bytes exceeds the %d byte payload limit", len(data), maxPayload)
	}

	var env envelope

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return zero, envelopeMeta{}, ErrInvalidSession.Wrap(err, "envelope: parse")
	}

	if dec.More() {
		return zero, envelopeMeta{}, ErrInvalidSession.Msg("envelope: trailing data")
	}

	switch {
	case env.Version != envelopeVersion:
		return zero, envelopeMeta{}, ErrInvalidSession.Msgf("envelope: unsupported version %d", env.Version)
	case env.CreatedAt <= 0 || env.ExpiresAt <= env.CreatedAt:
		return zero, envelopeMeta{}, ErrInvalidSession.Msg("envelope: invalid timestamps")
	case len(env.Data) == 0:
		return zero, envelopeMeta{}, ErrInvalidSession.Msg("envelope: missing data")
	}

	meta := envelopeMeta{
		CreatedAt: time.Unix(env.CreatedAt, 0),
		ExpiresAt: time.Unix(env.ExpiresAt, 0),
	}
	if !now.Before(meta.ExpiresAt) {
		return zero, envelopeMeta{}, ErrSessionExpired.Msg("envelope: session expired")
	}

	var values T

	if err := json.Unmarshal(env.Data, &values); err != nil {
		return zero, envelopeMeta{}, errors.ErrInternal.Wrap(err, "deserialize session values")
	}

	return values, meta, nil
}
