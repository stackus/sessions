package sessions

// ManagerOption configures a SessionManager.
type ManagerOption interface {
	configureManager(*managerConfig)
}

type managerConfig struct {
	gracefulDecodeFailure bool
}

type gracefulDecodeFailureOption struct{}

func (gracefulDecodeFailureOption) configureManager(cfg *managerConfig) {
	cfg.gracefulDecodeFailure = true
}

// WithGracefulDecodeFailure makes Get treat any Store.Get error as a miss and
// fall through to Store.New. Use when an expired or corrupted cookie should
// silently produce a new session rather than an error.
func WithGracefulDecodeFailure() ManagerOption {
	return gracefulDecodeFailureOption{}
}
