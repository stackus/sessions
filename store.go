package sessions

import (
	"context"
	crand "crypto/rand"
	"encoding/base32"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Store interface {
	Get(ctx context.Context, proxy *SessionProxy, cookieValue string) error
	New(ctx context.Context, proxy *SessionProxy) error
	Save(ctx context.Context, proxy *SessionProxy) error
}

type CookieStore struct{}

var _ Store = (*CookieStore)(nil)

func NewCookieStore() *CookieStore {
	return &CookieStore{}
}

func (cs CookieStore) Get(_ context.Context, proxy *SessionProxy, cookieValue string) error {
	return proxy.Decode([]byte(cookieValue), proxy.Values)
}

func (cs CookieStore) New(_ context.Context, _ *SessionProxy) error {
	// nothing to do
	return nil
}

func (cs CookieStore) Save(_ context.Context, proxy *SessionProxy) error {
	value, err := proxy.Encode(proxy.Values)
	if err != nil {
		return err
	}

	return proxy.Save(string(value))
}

type FileSystemStore struct {
	root        string
	maxFileSize int
}

var _ Store = (*FileSystemStore)(nil)

const sessionFilePrefix = "session_"

var fsMutex = &sync.Mutex{}

func NewFileSystemStore(root string, maxFileSize int) *FileSystemStore {
	return &FileSystemStore{
		root:        root,
		maxFileSize: maxFileSize,
	}
}

func (fs FileSystemStore) Get(_ context.Context, proxy *SessionProxy, cookieValue string) error {
	if err := proxy.Decode([]byte(cookieValue), &proxy.ID); err != nil {
		return err
	}

	data, err := fs.read(fs.fileName(proxy.ID))
	if err != nil {
		return err
	}

	return proxy.Decode(data, proxy.Values)
}

func (fs FileSystemStore) New(_ context.Context, _ *SessionProxy) error {
	// nothing to do
	return nil
}

func (fs FileSystemStore) Save(_ context.Context, proxy *SessionProxy) error {
	if proxy.MaxAge() <= 0 {
		if err := fs.delete(fs.fileName(proxy.ID)); err != nil {
			return err
		}
		return proxy.Delete()
	}

	if proxy.ID == "" {
		proxy.ID = randomID(32)
	}

	value, err := proxy.Encode(proxy.Values)
	if err != nil {
		return err
	}
	if err := fs.write(fs.fileName(proxy.ID), value); err != nil {
		return err
	}

	id, err := proxy.Encode(proxy.ID)
	if err != nil {
		return err
	}

	return proxy.Save(string(id))
}

func (fs FileSystemStore) fileName(id string) string {
	return filepath.Clean(filepath.Join(fs.root, sessionFilePrefix+id))
}

func (fs FileSystemStore) read(fileName string) ([]byte, error) {
	fsMutex.Lock()
	defer fsMutex.Unlock()
	return os.ReadFile(fileName)
}

func (fs FileSystemStore) write(fileName string, data []byte) error {
	// check data length against maxFileSize
	if fs.maxFileSize > 0 && len(data) > fs.maxFileSize {
		return ErrEncodedLengthTooLong
	}
	fsMutex.Lock()
	defer fsMutex.Unlock()
	return os.WriteFile(fileName, data, 0600)
}

func (fs FileSystemStore) delete(fileName string) error {
	fsMutex.Lock()
	defer fsMutex.Unlock()
	if err := os.Remove(fileName); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func randomID(length int) string {
	k := make([]byte, length)
	if _, err := io.ReadFull(crand.Reader, k); err != nil {
		return ""
	}
	return base32RawStdEncoding.EncodeToString(k)
}
