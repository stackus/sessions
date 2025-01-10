package sessions

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
)

// Flash is used to store messages for the current and next request
//
// Three types of messages can be stored:
// - Current request only: Add these messages with the Now(key, message) method.
// - Next request only: Add these messages with the Add(key, message) method.
// - Until read or removed: Add these messages with the Keep(key, message) method.
type Flash struct {
	flashes map[string]string
	now     map[string]string
	keep    map[string]string
}

type flash struct {
	Flashes map[string]string `json:"flashes"`
	Keep    map[string]string `json:"keep"`
}

func init() {
	gob.Register(Flash{})
	gob.Register(flash{})
}

// Get returns the flash message for the given key
// and deletes the message from the flash storage
func (f *Flash) Get(key string) string {
	var message string
	if f.now != nil && f.now[key] != "" {
		message = f.now[key]
	} else if f.flashes != nil && f.flashes[key] != "" {
		message = f.flashes[key]
	} else if f.keep != nil && f.keep[key] != "" {
		message = f.keep[key]
	}

	// delete the key from all possible locations
	if message != "" {
		delete(f.now, key)
		delete(f.flashes, key)
		delete(f.keep, key)
	}

	return message
}

// Add adds a flash message for the given key
//
// The stored flash message will be available until the next request.
func (f *Flash) Add(key, message string) {
	if message == "" {
		return
	}
	if f.flashes == nil {
		f.flashes = make(map[string]string)
	}
	f.flashes[key] = message
}

// Now adds a flash message for the given key
//
// The stored flash message will be available only for the current request.
func (f *Flash) Now(key, message string) {
	if message == "" {
		return
	}
	if f.now == nil {
		f.now = make(map[string]string)
	}
	f.now[key] = message
}

// Keep adds a flash message for the given key
//
// The stored flash message will be available until the message is read or removed.
func (f *Flash) Keep(key, message string) {
	if message == "" {
		return
	}
	if f.keep == nil {
		f.keep = make(map[string]string)
	}
	f.keep[key] = message
}

// Remove removes a flash message for the given key
func (f *Flash) Remove(key string) {
	delete(f.now, key)
	delete(f.flashes, key)
	delete(f.keep, key)
}

// Clear removes all flash messages
func (f *Flash) Clear() {
	f.now = nil
	f.flashes = nil
	f.keep = nil
}

// Support for gob encoding

// GobEncode encodes the flash messages for gob serialization
func (f *Flash) GobEncode() ([]byte, error) {
	ff := flash{
		Flashes: f.flashes,
		Keep:    f.keep,
	}
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(ff)
	return buf.Bytes(), err
}

// GobDecode decodes the flash messages for gob serialization
func (f *Flash) GobDecode(data []byte) error {
	buf := bytes.NewBuffer(data)
	ff := flash{}
	err := gob.NewDecoder(buf).Decode(&ff)
	if err != nil {
		return err
	}
	f.now = ff.Flashes
	f.keep = ff.Keep
	return nil
}

// Support for json encoding

// MarshalJSON encodes the flash messages for json serialization
func (f *Flash) MarshalJSON() ([]byte, error) {
	ff := flash{
		Flashes: f.flashes,
		Keep:    f.keep,
	}
	return json.Marshal(ff)
}

// UnmarshalJSON decodes the flash messages for json serialization
func (f *Flash) UnmarshalJSON(data []byte) error {
	ff := flash{}
	err := json.Unmarshal(data, &ff)
	if err != nil {
		return err
	}
	f.now = ff.Flashes
	f.keep = ff.Keep

	return nil
}

// Support for general encoding

// BinaryMarshal encodes the flash messages for binary serialization
func (f *Flash) BinaryMarshal() ([]byte, error) {
	return f.GobEncode()
}

// BinaryUnmarshal decodes the flash messages for binary serialization
func (f *Flash) BinaryUnmarshal(data []byte) error {
	return f.GobDecode(data)
}
