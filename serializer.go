package sessions

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
)

// Serializer is an interface for encoding and decoding session values.
// They are used by the Codec to serialize and deserialize session values.
//
// The following two implementations are provided:
//   - JsonSerializer
//   - GobSerializer
//
// You can also implement your own serializer if you have specific requirements.
// Use WithSerializer to set a custom serializer when creating a new codec.
type Serializer interface {
	Serialize(any) ([]byte, error)
	Deserialize([]byte, any) error
}

// JsonSerializer is a serializer that uses the encoding/json package to serialize and deserialize session values.
type JsonSerializer struct{}

var _ Serializer = (*JsonSerializer)(nil)

func (s JsonSerializer) Serialize(src any) ([]byte, error) {
	return json.Marshal(src)
}

func (s JsonSerializer) Deserialize(src []byte, dst any) error {
	return json.Unmarshal(src, dst)
}

// GobSerializer is a serializer that uses the encoding/gob package to serialize and deserialize session values.
//
// Note that the gob package requires that the type being serialized is registered with gob.Register.
//
// Example:
//
//	type MySessionData struct {
//	  // fields ...
//	}
//
//	func init() {
//	  gob.Register(MySessionData{})
//	}
type GobSerializer struct{}

var _ Serializer = (*GobSerializer)(nil)

func (s GobSerializer) Serialize(src any) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(src); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s GobSerializer) Deserialize(src []byte, dst any) error {
	return gob.NewDecoder(bytes.NewReader(src)).Decode(dst)
}
