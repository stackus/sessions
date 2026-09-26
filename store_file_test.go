package sessions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackus/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestFileStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sessions")
	store, err := NewFileStore(dir)
	require.NoError(t, err)
	return store, dir
}

// dirSnapshot lists every path under root, relative to root.
func dirSnapshot(t *testing.T, root string) []string {
	t.Helper()
	var paths []string
	err := filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		paths = append(paths, rel)
		return err
	})
	require.NoError(t, err)
	return paths
}

func TestNewFileStore(t *testing.T) {
	t.Run("creates missing directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "a", "b")
		_, err := NewFileStore(dir)
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		}
	})

	t.Run("accepts existing directory", func(t *testing.T) {
		_, err := NewFileStore(t.TempDir())
		require.NoError(t, err)
	})

	invalid := map[string]func(t *testing.T) string{
		"empty path": func(t *testing.T) string {
			return ""
		},
		"path is a file": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(path, nil, 0o600))
			return path
		},
	}
	for name, setup := range invalid {
		t.Run(name, func(t *testing.T) {
			store, err := NewFileStore(setup(t))
			require.Error(t, err)
			assert.Nil(t, store)
			assert.True(t, errors.Is(err, errors.ErrInvalidArgument))
		})
	}
}

func TestFileStore_CreateLoadUpdate(t *testing.T) {
	store, dir := newTestFileStore(t)

	id, err := store.Create(t.Context(), []byte("v1"), testStoreParams())
	require.NoError(t, err)
	assert.Len(t, id, 43)
	assert.True(t, validFileStoreID(id))

	info, err := os.Stat(filepath.Join(dir, "session_"+id))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	loaded, err := store.Load(t.Context(), id, testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, []byte("v1"), loaded)

	updated, err := store.Update(t.Context(), id, []byte("v2"), testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, id, updated, "FileStore keeps a stable credential")

	loaded, err = store.Load(t.Context(), id, testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, []byte("v2"), loaded)

	assert.Equal(t, []string{".", "session_" + id}, dirSnapshot(t, dir), "no temporary files left behind")
}

func TestFileStore_UniqueIDs(t *testing.T) {
	store, _ := newTestFileStore(t)
	seen := make(map[string]bool)
	for range 100 {
		id, err := store.Create(t.Context(), []byte("data"), testStoreParams())
		require.NoError(t, err)
		assert.False(t, seen[id])
		seen[id] = true
	}
}

func TestFileStore_InvalidCredentials(t *testing.T) {
	valid := strings.Repeat("A", 43)
	tests := map[string]string{
		"empty":           "",
		"traversal":       "../../../../../../../../../../../etc/passwd",
		"traversal sized": "../" + valid[3:],
		"slash":           valid[:20] + "/" + valid[21:],
		"backslash":       valid[:20] + `\` + valid[21:],
		"dot":             valid[:42] + ".",
		"too short":       valid[:42],
		"too long":        valid + "A",
		"bad alphabet":    valid[:42] + "+",
		"null byte":       valid[:42] + "\x00",
		"absolute":        "/" + valid[1:],
	}

	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	require.NoError(t, os.WriteFile(sentinel, []byte("untouched"), 0o600))

	store, dir := newTestFileStore(t)
	before := dirSnapshot(t, dir)

	for name, credential := range tests {
		t.Run(name, func(t *testing.T) {
			loaded, loadErr := store.Load(t.Context(), credential, testStoreParams())
			assert.Nil(t, loaded)
			updated, updateErr := store.Update(t.Context(), credential, []byte("x"), testStoreParams())
			assert.Empty(t, updated)
			deleteErr := store.Delete(t.Context(), credential)

			for op, err := range map[string]error{"Load": loadErr, "Update": updateErr, "Delete": deleteErr} {
				assert.True(t, errors.Is(err, ErrInvalidSession), "%s: %v", op, err)
				if err != nil && credential != "" {
					assert.NotContains(t, err.Error(), credential, op)
				}
			}
		})
	}

	assert.Equal(t, before, dirSnapshot(t, dir), "store directory must be unchanged")
	data, err := os.ReadFile(sentinel)
	require.NoError(t, err)
	assert.Equal(t, "untouched", string(data))
}

func TestFileStore_MissingRecord(t *testing.T) {
	store, dir := newTestFileStore(t)
	missing := strings.Repeat("B", 43)

	loaded, err := store.Load(t.Context(), missing, testStoreParams())
	assert.Nil(t, loaded)
	assert.True(t, errors.Is(err, ErrSessionNotFound))
	assert.Equal(t, "SESSION_NOT_FOUND", errors.TypeCode(err))

	updated, err := store.Update(t.Context(), missing, []byte("x"), testStoreParams())
	assert.Empty(t, updated)
	assert.True(t, errors.Is(err, ErrSessionNotFound))
	assert.Equal(t, []string{"."}, dirSnapshot(t, dir), "Update must not create a missing record")

	assert.NoError(t, store.Delete(t.Context(), missing))
}

func TestFileStore_DeleteIsIdempotent(t *testing.T) {
	store, dir := newTestFileStore(t)
	id, err := store.Create(t.Context(), []byte("data"), testStoreParams())
	require.NoError(t, err)

	require.NoError(t, store.Delete(t.Context(), id))
	require.NoError(t, store.Delete(t.Context(), id))
	assert.Equal(t, []string{"."}, dirSnapshot(t, dir))

	_, err = store.Load(t.Context(), id, testStoreParams())
	assert.True(t, errors.Is(err, ErrSessionNotFound))
}

func TestFileStore_LoadSizeLimit(t *testing.T) {
	store, _ := newTestFileStore(t)
	params := testStoreParams()
	params.MaxRecordSize = 8

	id, err := store.Create(t.Context(), make([]byte, 8), params)
	require.NoError(t, err)
	loaded, err := store.Load(t.Context(), id, params)
	require.NoError(t, err)
	assert.Len(t, loaded, 8)

	_, err = store.Update(t.Context(), id, make([]byte, 9), params)
	require.NoError(t, err, "the manager enforces the limit on writes")

	// A record beyond the limit is rejected, not read.
	loaded, err = store.Load(t.Context(), id, params)
	assert.Nil(t, loaded)
	assert.True(t, errors.Is(err, ErrInvalidSession))
}

func TestFileStore_ModTimeIsExpiry(t *testing.T) {
	store, dir := newTestFileStore(t)
	params := testStoreParams()
	params.ExpiresAt = time.Unix(1_900_000_000, 0)

	id, err := store.Create(t.Context(), []byte("v1"), params)
	require.NoError(t, err)
	info, err := os.Stat(filepath.Join(dir, "session_"+id))
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(params.ExpiresAt), "Create sets the expiry")

	params.ExpiresAt = params.ExpiresAt.Add(time.Hour)
	_, err = store.Update(t.Context(), id, []byte("v2"), params)
	require.NoError(t, err)
	info, err = os.Stat(filepath.Join(dir, "session_"+id))
	require.NoError(t, err)
	assert.True(t, info.ModTime().Equal(params.ExpiresAt), "Update moves the expiry")
}

func TestFileStore_RandomFailure(t *testing.T) {
	store, dir := newTestFileStore(t)
	store.rand = failingReader{}

	id, err := store.Create(t.Context(), []byte("data"), testStoreParams())
	require.Error(t, err)
	assert.Empty(t, id)
	assert.False(t, IsNoSession(err))
	assert.Equal(t, "INTERNAL", errors.TypeCode(err))
	assert.Equal(t, []string{"."}, dirSnapshot(t, dir))
}

func TestFileStore_InterruptedUpdateKeepsOldRecord(t *testing.T) {
	store, dir := newTestFileStore(t)
	id, err := store.Create(t.Context(), []byte("old"), testStoreParams())
	require.NoError(t, err)

	store.rename = func(string, string) error { return fmt.Errorf("simulated crash before rename") }
	_, err = store.Update(t.Context(), id, []byte("new"), testStoreParams())
	require.Error(t, err)
	assert.False(t, IsNoSession(err))

	loaded, err := store.Load(t.Context(), id, testStoreParams())
	require.NoError(t, err)
	assert.Equal(t, []byte("old"), loaded)
	assert.Equal(t, []string{".", "session_" + id}, dirSnapshot(t, dir), "temporary file removed")
}

func TestFileStore_PermissionErrorIsOperational(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions are not enforced here")
	}
	store, dir := newTestFileStore(t)
	id, err := store.Create(t.Context(), []byte("data"), testStoreParams())
	require.NoError(t, err)

	path := filepath.Join(dir, "session_"+id)
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	loaded, err := store.Load(t.Context(), id, testStoreParams())
	assert.Nil(t, loaded)
	require.Error(t, err)
	assert.False(t, IsNoSession(err))
	assert.Equal(t, "INTERNAL", errors.TypeCode(err))
	assert.NotContains(t, err.Error(), id, "credential must not appear in the error")
	assert.Contains(t, err.Error(), "permission denied")
}

func TestFileStore_Cleanup(t *testing.T) {
	store, dir := newTestFileStore(t)
	now := time.Now().Truncate(time.Second)
	old := now.Add(-2 * time.Hour)
	store.now = func() time.Time { return now }

	expired, err := store.Create(t.Context(), []byte("expired"), StoreParams{ExpiresAt: now.Add(-time.Second)})
	require.NoError(t, err)

	fresh, err := store.Create(t.Context(), []byte("fresh"), StoreParams{ExpiresAt: now.Add(time.Second)})
	require.NoError(t, err)

	staleTemp := filepath.Join(dir, ".tmp-session_123")
	require.NoError(t, os.WriteFile(staleTemp, nil, 0o600))
	require.NoError(t, os.Chtimes(staleTemp, old, old))

	recentTemp := filepath.Join(dir, ".tmp-session_456")
	require.NoError(t, os.WriteFile(recentTemp, nil, 0o600))
	require.NoError(t, os.Chtimes(recentTemp, now.Add(-time.Minute), now.Add(-time.Minute)))

	foreign := []string{"notes.txt", "session_short", "session_" + strings.Repeat("C", 43) + ".bak"}
	for _, name := range foreign {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.NoError(t, os.Chtimes(path, old, old))
	}

	require.NoError(t, store.Cleanup(t.Context()))

	_, err = store.Load(t.Context(), expired, testStoreParams())
	assert.True(t, errors.Is(err, ErrSessionNotFound), "expired record removed")
	_, err = store.Load(t.Context(), fresh, testStoreParams())
	assert.NoError(t, err, "unexpired record kept")
	assert.NoFileExists(t, staleTemp, "stale temporary file removed")
	assert.FileExists(t, recentTemp, "temporary file of a write in progress kept")
	for _, name := range foreign {
		assert.FileExists(t, filepath.Join(dir, name), "foreign file kept")
	}
}

func TestFileStore_Cleanup_CancelledContext(t *testing.T) {
	store, _ := newTestFileStore(t)
	id, err := store.Create(t.Context(), []byte("data"), StoreParams{ExpiresAt: time.Now().Add(-time.Hour)})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = store.Cleanup(ctx)
	assert.ErrorIs(t, err, context.Canceled)

	_, err = store.Load(t.Context(), id, testStoreParams())
	assert.NoError(t, err, "nothing removed after cancellation")
}

func TestFileStore_Concurrent(t *testing.T) {
	store, _ := newTestFileStore(t)
	shared, err := store.Create(t.Context(), []byte("shared"), testStoreParams())
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for j := range 25 {
				id, err := store.Create(t.Context(), fmt.Appendf(nil, "%d-%d", i, j), testStoreParams())
				if !assert.NoError(t, err) {
					return
				}
				_, err = store.Update(t.Context(), id, []byte("updated"), testStoreParams())
				assert.NoError(t, err)
				data, err := store.Load(t.Context(), id, testStoreParams())
				assert.NoError(t, err)
				assert.Equal(t, []byte("updated"), data)

				_, err = store.Update(t.Context(), shared, fmt.Appendf(nil, "w%d", i), testStoreParams())
				assert.NoError(t, err)
				_, err = store.Load(t.Context(), shared, testStoreParams())
				assert.NoError(t, err)
			}
		})
	}
	wg.Go(func() {
		for range 10 {
			assert.NoError(t, store.Cleanup(t.Context()))
		}
	})
	wg.Wait()
}

func TestRedactPath(t *testing.T) {
	_, err := os.Open(filepath.Join(t.TempDir(), "session_secret-id"))
	require.Error(t, err)

	redacted := redactPath(err)
	assert.NotContains(t, redacted.Error(), "secret-id")
	assert.ErrorIs(t, redacted, os.ErrNotExist)

	linkErr := os.Rename(filepath.Join(t.TempDir(), "missing-secret"), filepath.Join(t.TempDir(), "session_secret-id"))
	require.Error(t, linkErr)
	assert.NotContains(t, redactPath(linkErr).Error(), "secret")
}
