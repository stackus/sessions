package sessions

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
)

type sessionHash[T any] struct {
	Data    T
	Options CookieOptions
}

func (s *sessionHash[T]) Hash() ([]byte, error) {
	// compute hash of the session data
	hasher := sha256.New()

	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	_, err = hasher.Write(data)
	if err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func (s *sessionHash[T]) Compare(otherHash []byte) (bool, error) {
	// compute hash of the session data
	hash, err := s.Hash()
	if err != nil {
		return false, err
	}

	// compare the hashes
	return slices.Equal(hash, otherHash), nil
}
