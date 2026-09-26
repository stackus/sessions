package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/stackus/errors"
)

const (
	fileStoreIDBytes      = 32
	fileStoreIDLength     = 43 // base64.RawURLEncoding.EncodedLen(fileStoreIDBytes)
	fileStoreRecordPrefix = "session_"
	fileStoreTempPrefix   = ".tmp-session_"

	// fileStoreTempGrace is how far past its modification time Cleanup leaves
	// a temporary file alone, so it never removes one a write is still using.
	fileStoreTempGrace = time.Hour
)

// FileStore is a server-side store that keeps each record in its own file,
// named after an unguessable random ID. The ID is the credential given to the
// client.
//
// The records on disk are exactly what the manager's encoder produced. With
// Base64Encoder they are neither encrypted nor authenticated, so anyone who
// can read or write the directory can read or change sessions; use
// AESGCMEncoder when the storage environment is not trusted. The directory is
// created with mode 0700 and records with mode 0600.
//
// Each record file's modification time is set to the session's expiry, so
// Cleanup can find expired records without decoding them. The manager enforces
// session expiration on every load, whatever remains on disk. Expired files
// stay until Cleanup removes them.
//
// FileStore is safe for concurrent use within one process. Several processes
// sharing one directory get atomic writes, but an update racing a delete in
// another process may bring the deleted record back. On Windows, a file that is
// open cannot be replaced or removed, so a write racing a read in another
// process can fail with an operational error.
type FileStore struct {
	dir    string
	mu     sync.RWMutex // write-held for replace/remove, read-held while reading a record
	rand   io.Reader
	rename func(oldpath, newpath string) error
	now    func() time.Time
}

var _ Store = (*FileStore)(nil)

// NewFileStore returns a FileStore that keeps records in dir, creating it with
// mode 0700 if it does not exist.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.ErrInvalidArgument.Msg("file store: directory is required")
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, errors.ErrInvalidArgument.Wrap(err, "file store: resolve directory")
	}

	s := &FileStore{
		dir:    abs,
		rand:   rand.Reader,
		rename: os.Rename,
		now:    time.Now,
	}

	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, errors.ErrInvalidArgument.Wrap(err, "file store: create directory")
	}

	info, err := os.Stat(abs)
	if err != nil {
		return nil, errors.ErrInvalidArgument.Wrap(err, "file store: stat directory")
	}

	if !info.IsDir() {
		return nil, errors.ErrInvalidArgument.Msg("file store: path is not a directory")
	}

	return s, nil
}

// Load returns the record for credential. A record larger than
// params.MaxRecordSize returns ErrInvalidSession without being read in full.
func (s *FileStore) Load(_ context.Context, credential string, params StoreParams) ([]byte, error) {
	path, err := s.recordPath(credential)
	if err != nil {
		return nil, err
	}

	// Windows cannot replace or remove a file that is open, so reads exclude
	// replace and remove.
	s.mu.RLock()
	defer s.mu.RUnlock()

	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrSessionNotFound.Msg("file store: record not found")
		}
		return nil, errors.ErrInternal.Wrap(redactPath(err), "file store: open record")
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, int64(params.MaxRecordSize)+1))
	if err != nil {
		return nil, errors.ErrInternal.Wrap(redactPath(err), "file store: read record")
	}

	if len(data) > params.MaxRecordSize {
		return nil, ErrInvalidSession.Msg("file store: record too large")
	}

	return data, nil
}

// Create stores data under a new random ID, with a modification time of
// params.ExpiresAt, and returns the ID.
func (s *FileStore) Create(_ context.Context, data []byte, params StoreParams) (string, error) {
	id, err := s.newID()
	if err != nil {
		return "", err
	}

	tmpPath, err := s.writeTemp(data, params.ExpiresAt)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpPath)

	// The record appears complete and with its expiry already set, so Cleanup
	// never mistakes it for an expired one. Link never overwrites an existing
	// record.
	if err := os.Link(tmpPath, filepath.Join(s.dir, fileStoreRecordPrefix+id)); err != nil {
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: create record")
	}

	return id, nil
}

// Update atomically replaces the record for credential, with a modification
// time of params.ExpiresAt, and returns the same credential. It does not create
// a missing record.
func (s *FileStore) Update(_ context.Context, credential string, data []byte, params StoreParams) (string, error) {
	path, err := s.recordPath(credential)
	if err != nil {
		return "", err
	}

	tmpPath, err := s.writeTemp(data, params.ExpiresAt)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmpPath) // no-op once renamed

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrSessionNotFound.Msg("file store: record not found")
		}
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: stat record")
	}

	if err := s.rename(tmpPath, path); err != nil {
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: replace record")
	}

	return credential, nil
}

// Delete removes the record for credential. Deleting a missing record
// succeeds. A malformed credential returns ErrInvalidSession and touches
// nothing.
func (s *FileStore) Delete(_ context.Context, credential string) error {
	path, err := s.recordPath(credential)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.ErrInternal.Wrap(redactPath(err), "file store: delete record")
	}

	return nil
}

// Cleanup removes expired records, whose modification time (their expiry) has
// passed, and temporary files left by interrupted writes once their
// modification time is more than an hour past. Other files in the directory
// are left alone. The application calls Cleanup on its own schedule.
func (s *FileStore) Cleanup(ctx context.Context) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return errors.ErrInternal.Wrap(err, "file store: read directory")
	}

	now := s.now()

	var errs []error

	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if !entry.Type().IsRegular() || !isFileStoreName(name) {
			continue
		}
		cutoff := now
		if strings.HasPrefix(name, fileStoreTempPrefix) {
			cutoff = now.Add(-fileStoreTempGrace)
		}
		if err := s.removeIfOlder(filepath.Join(s.dir, name), cutoff); err != nil {
			errs = append(errs, redactPath(err))
		}
	}
	if len(errs) > 0 {
		return errors.ErrInternal.Wrap(errors.Join(errs...), "file store: cleanup")
	}

	return nil
}

func (s *FileStore) removeIfOlder(path string, cutoff time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}

	if !info.ModTime().Before(cutoff) {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

// writeTemp writes data to a new temporary file whose modification time is
// expiresAt and returns its path. The caller removes it.
func (s *FileStore) writeTemp(data []byte, expiresAt time.Time) (string, error) {
	tmp, err := os.CreateTemp(s.dir, fileStoreTempPrefix+"*")
	if err != nil {
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: create temporary record")
	}

	tmpPath := tmp.Name()

	if err := writeAndClose(tmp, data); err != nil {
		_ = os.Remove(tmpPath)
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: write temporary record")
	}

	if err := os.Chtimes(tmpPath, time.Time{}, expiresAt); err != nil {
		_ = os.Remove(tmpPath)
		return "", errors.ErrInternal.Wrap(redactPath(err), "file store: set record expiry")
	}

	return tmpPath, nil
}

// recordPath validates credential and returns its record path. No path is
// ever built from an unvalidated credential.
func (s *FileStore) recordPath(credential string) (string, error) {
	if !validFileStoreID(credential) {
		return "", ErrInvalidSession.Msg("file store: malformed credential")
	}

	path := filepath.Join(s.dir, fileStoreRecordPrefix+credential)

	if filepath.Dir(path) != s.dir {
		return "", ErrInvalidSession.Msg("file store: malformed credential")
	}

	return path, nil
}

func (s *FileStore) newID() (string, error) {
	b := make([]byte, fileStoreIDBytes)

	if _, err := io.ReadFull(s.rand, b); err != nil {
		return "", errors.ErrInternal.Wrap(err, "file store: generate id")
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// validFileStoreID reports whether id is exactly a 43-character base64url
// string, the only form Create produces.
func validFileStoreID(id string) bool {
	if len(id) != fileStoreIDLength {
		return false
	}

	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}

	return true
}

func isFileStoreName(name string) bool {
	if id, ok := strings.CutPrefix(name, fileStoreRecordPrefix); ok {
		return validFileStoreID(id)
	}

	return strings.HasPrefix(name, fileStoreTempPrefix)
}

func writeAndClose(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}

	if cerr := f.Close(); err == nil {
		err = cerr
	}

	return err
}

// redactPath removes file paths from OS errors, because record paths contain
// credentials. The underlying error is kept, so errors.Is still matches
// fs.ErrNotExist and similar.
func redactPath(err error) error {
	var pathErr *fs.PathError

	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %w", pathErr.Op, pathErr.Err)
	}

	var linkErr *os.LinkError

	if errors.As(err, &linkErr) {
		return fmt.Errorf("%s: %w", linkErr.Op, linkErr.Err)
	}

	return err
}
