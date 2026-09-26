package sessions

import (
	"crypto/rand"
	"testing"
	"time"
)

// randomBytes returns n bytes from crypto/rand, failing the test on error.
func randomBytes(t testing.TB, n int) []byte {
	t.Helper()

	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}

	return b
}

// testStoreParams returns store params for direct store calls in tests: the
// default record size limit and an expiry an hour from now.
func testStoreParams() StoreParams {
	return StoreParams{ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second), MaxRecordSize: defaultMaxRecordSize}
}

// testTransportParams returns transport params for direct transport calls in
// tests: an expiry an hour from now.
func testTransportParams() TransportParams {
	return TransportParams{ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second)}
}
