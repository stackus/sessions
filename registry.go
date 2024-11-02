package sessions

import (
	"context"
	"net/http"

	"github.com/stackus/errors"
)

type registrySession interface {
	Save(w http.ResponseWriter, r *http.Request) error
}

type contextKey int

const sessionsKey contextKey = 10912

type registry struct {
	sessions map[string]registrySession
}

func getRegistry(r *http.Request) *registry {
	ctx := r.Context()

	if reg := ctx.Value(sessionsKey); reg != nil {
		return reg.(*registry)
	}

	reg := &registry{
		sessions: make(map[string]registrySession),
	}

	*r = *r.WithContext(context.WithValue(ctx, sessionsKey, reg))

	return reg
}

func (r *registry) get(name string) any {
	return r.sessions[name]
}

func (r *registry) set(name string, session registrySession) {
	r.sessions[name] = session
}

// Save saves all sessions in the registry for the provided request.
func Save(w http.ResponseWriter, r *http.Request) error {
	reg := getRegistry(r)

	var errs []error
	for name, session := range reg.sessions {
		if err := session.Save(w, r); err != nil {
			errs = append(errs, errors.ErrInternalServerError.Wrapf(err, "registry: error while saving session: %q", name))
		}
	}
	return errors.Join(errs...)
}
