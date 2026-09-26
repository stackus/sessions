package sessions

import (
	"testing"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCookieStore_CreateLoad(t *testing.T) {
	records := map[string][]byte{
		"empty":  {},
		"text":   []byte("encoded record"),
		"binary": {0x00, 0xff, 0xfb, 0x80},
	}
	store := NewCookieStore()
	for name, record := range records {
		t.Run(name, func(t *testing.T) {
			credential, err := store.Create(t.Context(), record, testStoreParams())
			require.NoError(t, err)
			assert.NotContains(t, credential, "=", "credential must be unpadded")
			assert.NotContains(t, credential, "+", "credential must be URL-safe")
			assert.NotContains(t, credential, "/", "credential must be URL-safe")

			loaded, err := store.Load(t.Context(), credential, testStoreParams())
			require.NoError(t, err)
			assert.Equal(t, record, loaded)
		})
	}
}

func TestCookieStore_Update(t *testing.T) {
	store := NewCookieStore()
	original, err := store.Create(t.Context(), []byte("v1"), testStoreParams())
	require.NoError(t, err)

	updated, err := store.Update(t.Context(), original, []byte("v2"), testStoreParams())
	require.NoError(t, err)
	assert.NotEqual(t, original, updated, "credential changes when the record does")

	loaded, err := store.Load(t.Context(), updated, testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), loaded)
}

func TestCookieStore_Load_Malformed(t *testing.T) {
	tests := map[string]string{
		"invalid character":   "not base64!",
		"padding":             "-_8=",
		"standard alphabet":   "+/8",
		"impossible length":   "abcde",
		"non-zero extra bits": "-_9",
	}
	store := NewCookieStore()
	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			loaded, err := store.Load(t.Context(), credential, testStoreParams())
			require.Error(t, err)
			assert.Nil(t, loaded)
			assert.True(t, errors.Is(err, ErrInvalidSession))
			assert.Equal(t, "SESSION_INVALID", errors.TypeCode(err))
			assert.True(t, IsNoSession(err))
			assert.NotContains(t, err.Error(), credential, "credential must not appear in the error")
		})
	}
}

func TestCookieStore_Delete(t *testing.T) {
	store := NewCookieStore()
	for _, credential := range []string{"", "not base64!", "dmFsaWQ"} {
		assert.NoError(t, store.Delete(t.Context(), credential))
	}
}

func TestCookieStore_NoAliasing(t *testing.T) {
	store := NewCookieStore()
	record := []byte("encoded record")
	credential, err := store.Create(t.Context(), record, testStoreParams())
	require.NoError(t, err)
	record[0] = 'X'

	loaded, err := store.Load(t.Context(), credential, testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, "encoded record", string(loaded), "Create must not retain its input")

	again, err := store.Load(t.Context(), credential, testStoreParams())
	require.NoError(t, err)
	loaded[0] = 'Y'
	assert.Equal(t, "encoded record", string(again), "each Load returns its own slice")
}
