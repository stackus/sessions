package sessions

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackus/errors"
)

// Invariants for every fuzz target: no panic; errors from malformed input are
// expected rejections (IsNoSession or ErrInvalidEncoding), never partial
// values; and the file store never touches anything outside its directory.

// fuzzLoad runs Load for r through m and checks the invariants.
func fuzzLoad(t *testing.T, m *Manager[testSession], r *http.Request) {
	m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, err := m.Load(r)
		switch {
		case err == nil && sess == nil:
			t.Fatal("nil session without error")
		case err != nil && sess != nil:
			t.Fatal("session returned with error")
		case err != nil && !IsNoSession(err):
			t.Fatalf("malformed input produced an operational error: %v", err)
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
}

func FuzzManagerLoad_Cookie(f *testing.F) {
	hmacEnc, err := NewHMACEncoder(make([]byte, 32))
	if err != nil {
		f.Fatal(err)
	}
	cookieStore := newCookieManagerF(f, hmacEnc, NewCookieStore())
	fileStore, err := NewFileStore(f.TempDir())
	if err != nil {
		f.Fatal(err)
	}
	serverSide := newCookieManagerF(f, NewBase64Encoder(), fileStore)

	// A valid credential for each manager, plus malformed seeds.
	valid := issueF(f, hmacEnc, NewCookieStore())
	validID := issueF(f, NewBase64Encoder(), fileStore)
	for _, seed := range []string{
		"session=" + valid,
		"session=" + validID, "session=" + valid[:len(valid)-2],
		"", "session=",
		"session=a; session=b",
		"session=" + strings.Repeat("A", 5000),
		"session=../../etc/passwd",
		`session="quoted"`, "session=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, cookieHeader string) {
		for _, m := range []*Manager[testSession]{cookieStore, serverSide} {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Header.Set("Cookie", cookieHeader)
			fuzzLoad(t, m, r)
		}
	})
}

func FuzzManagerLoad_Bearer(f *testing.F) {
	aesEnc, err := NewAESGCMEncoder(make([]byte, 32))
	if err != nil {
		f.Fatal(err)
	}
	transport, err := NewBearerTransport()
	if err != nil {
		f.Fatal(err)
	}
	m, err := NewManager[testSession](transport, aesEnc, NewCookieStore())
	if err != nil {
		f.Fatal(err)
	}
	valid := issueF(f, aesEnc, NewCookieStore())
	for _, seed := range []string{
		"Bearer " + valid,
		"Bearer " + valid[:10],
		"bearer x", "Basic abc",
		"Bearer", "Bearer a b",
		"Bearer ====", "Bearer " + strings.Repeat("x", 5000), "",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, authorization string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", authorization)
		fuzzLoad(t, m, r)
	})
}

func FuzzBearerTransport_Read(f *testing.F) {
	transport, err := NewBearerTransport(BearerTransportMaxCredentialSize(64))
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"Bearer abc", "bearer   a=", "Bearer a b", "Basic x", "Bearer", "Bearer =", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, authorization string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", authorization)
		token, err := transport.Read(r)
		if err != nil {
			if token != "" {
				t.Fatal("token returned with error")
			}
			if !errors.Is(err, ErrNoCredential) && !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("unexpected error class: %v", err)
			}
			return
		}
		if !isToken68(token) || len(token) > 64 {
			t.Fatalf("accepted invalid token %q", token)
		}
	})
}

func FuzzUnmarshalEnvelope(f *testing.F) {
	valid, err := marshalEnvelope(testSession{UserID: 1, Roles: []string{"a"}}, envelopeMeta{
		CreatedAt: time.Unix(1_700_000_000, 0), ExpiresAt: time.Unix(1_800_000_000, 0),
	}, defaultMaxPayloadSize)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{
		valid,
		valid[:len(valid)/2],
		append(append([]byte{}, valid...), '}'),
		[]byte(`{"v":2,"c":1,"e":2,"d":{}}`),
		[]byte(`{"v":1,"c":1,"e":2,"d":{"user_id":"x"}}`),
		[]byte(strings.Repeat("[", 10000)),
		{},
		[]byte("null"),
	} {
		f.Add(seed)
	}
	now := time.Unix(1_750_000_000, 0)

	f.Fuzz(func(t *testing.T, data []byte) {
		values, meta, err := unmarshalEnvelope[testSession](data, now, 1024)
		if err == nil {
			return
		}
		if values.UserID != 0 || values.Roles != nil || !meta.CreatedAt.IsZero() || !meta.ExpiresAt.IsZero() {
			t.Fatal("partial values returned with error")
		}
		if !IsNoSession(err) && !errors.Is(err, errors.ErrInternal) {
			t.Fatalf("unexpected error class: %v", err)
		}
	})
}

func FuzzEncoderDecode(f *testing.F) {
	key := make([]byte, 32)
	hmacEnc, err := NewHMACEncoder(key, WithEncoderLabel("fuzz"))
	if err != nil {
		f.Fatal(err)
	}
	aesEnc, err := NewAESGCMEncoder(key)
	if err != nil {
		f.Fatal(err)
	}
	rotating, err := NewRotatingEncoder(aesEnc, hmacEnc)
	if err != nil {
		f.Fatal(err)
	}
	encoders := map[string]Encoder{"hmac": hmacEnc, "aes-gcm": aesEnc, "rotating": rotating}

	for _, enc := range encoders {
		valid, err := enc.Encode([]byte("payload"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(valid)
		f.Add(valid[:len(valid)-1])
	}
	f.Add([]byte{})
	f.Add([]byte("not base64 !"))

	f.Fuzz(func(t *testing.T, data []byte) {
		for name, enc := range map[string]Encoder{
			"base64": NewBase64Encoder(), "hmac": hmacEnc, "aes-gcm": aesEnc, "rotating": rotating,
		} {
			out, err := enc.Decode(data)
			if err == nil {
				continue
			}
			if out != nil {
				t.Fatalf("%s: output returned with error", name)
			}
			if !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("%s: malformed input produced a non-encoding error: %v", name, err)
			}
		}
	})
}

func FuzzFileStoreCredential(f *testing.F) {
	root := f.TempDir()
	dir := filepath.Join(root, "store")
	store, err := NewFileStore(dir)
	if err != nil {
		f.Fatal(err)
	}
	sentinel := filepath.Join(root, "sentinel")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"",
		"..",
		"../sentinel",
		"/etc/passwd",
		strings.Repeat("A", 43),
		strings.Repeat("A", 42) + "/",
		"../" + strings.Repeat("A", 40),
		strings.Repeat(".", 43),
		"C:" + strings.Repeat("A", 41),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, credential string) {
		_, loadErr := store.Load(t.Context(), credential, testStoreParams())
		_, updateErr := store.Update(t.Context(), credential, []byte("x"), testStoreParams())
		deleteErr := store.Delete(t.Context(), credential)

		want := ErrSessionNotFound
		if !validFileStoreID(credential) {
			want = ErrInvalidSession
		}
		if !errors.Is(loadErr, want) || !errors.Is(updateErr, want) {
			t.Fatalf("Load/Update = %v / %v, want %v", loadErr, updateErr, want)
		}
		if deleteErr != nil && !errors.Is(deleteErr, ErrInvalidSession) {
			t.Fatalf("Delete = %v", deleteErr)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("store directory changed: %v", entries)
		}
		data, err := os.ReadFile(sentinel)
		if err != nil || string(data) != "untouched" {
			t.Fatal("file outside the store touched")
		}
	})
}

// newCookieManagerF is newCookieManager for fuzz setup.
func newCookieManagerF(f *testing.F, encoder Encoder, store Store) *Manager[testSession] {
	f.Helper()
	transport, err := NewCookieTransport("session", CookieTransportSecure(false))
	if err != nil {
		f.Fatal(err)
	}
	m, err := NewManager[testSession](transport, encoder, store)
	if err != nil {
		f.Fatal(err)
	}
	return m
}

// issueF stores a valid, unexpired record and returns its credential.
func issueF(f *testing.F, encoder Encoder, store Store) string {
	f.Helper()
	now := time.Now()
	payload, err := marshalEnvelope(testSession{UserID: 1}, envelopeMeta{CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, defaultMaxPayloadSize)
	if err != nil {
		f.Fatal(err)
	}
	record, err := encoder.Encode(payload)
	if err != nil {
		f.Fatal(err)
	}
	credential, err := store.Create(f.Context(), record, testStoreParams())
	if err != nil {
		f.Fatal(err)
	}
	return credential
}
