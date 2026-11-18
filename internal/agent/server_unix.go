//go:build unix

package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Arntek/secrets-vault/internal/crypto"
)

const (
	connIdle     = 10 * time.Second
	maxConns     = 64
	shutdownWait = 2 * time.Second
)

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// server is one running agent.
type server struct {
	opts   ServerOptions
	dir    string
	path   string
	ln     net.Listener
	store  *store
	log    *slog.Logger
	stop   chan struct{}
	once   sync.Once
	conns  sync.WaitGroup
	sem    chan struct{}
	sockFI os.FileInfo

	// peerCheck authorizes each connection; tests replace it.
	peerCheck atomic.Pointer[func(net.Conn) error]
}

// Serve runs the agent until ctx ends, a shutdown request arrives, or it has
// held no keys for opts.IdleExit. It returns ErrAlreadyRunning if a live
// agent owns the socket, and ErrUnsafeDir if the socket directory is not
// private to the current user.
func Serve(ctx context.Context, opts ServerOptions) error {
	s, err := newServer(opts)
	if err != nil {
		return err
	}
	return s.serve(ctx)
}

func newServer(opts ServerOptions) (*server, error) {
	opts = opts.withDefaults()
	dir := opts.Dir
	if dir == "" {
		d, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = d
	}
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	// Serialize concurrent starts: only one process may check, clean up and
	// bind at a time.
	lf, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- inside the verified private dir
	if err != nil {
		return nil, err
	}
	defer lf.Close()
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- fd fits int
		return nil, err
	}

	path := filepath.Join(dir, sockName)
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%w: %s exists and is not a socket", ErrUnsafeDir, sockName)
		}
		if c, derr := net.DialTimeout("unix", path, time.Second); derr == nil {
			_ = c.Close()
			return nil, ErrAlreadyRunning
		}
		if err := os.Remove(path); err != nil { // stale socket from a dead agent
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil { // dir is 0700, so nobody could connect in between
		_ = ln.Close()
		return nil, err
	}
	fi, _ := os.Lstat(path)
	srv := &server{
		opts: opts, dir: dir, path: path, ln: ln, sockFI: fi,
		store: newStore(opts.Now), log: opts.Logger,
		stop: make(chan struct{}), sem: make(chan struct{}, maxConns),
	}
	srv.setPeerCheck(checkPeer)
	return srv, nil
}

func (s *server) setPeerCheck(f func(net.Conn) error) { s.peerCheck.Store(&f) }

func (s *server) shutdown() { s.once.Do(func() { close(s.stop) }) }

// tick destroys expired keys and stops the agent once it has been empty for
// IdleExit. Called on a timer; tests call it directly with a fake clock.
func (s *server) tick() {
	if idle := s.store.reap(); idle >= s.opts.IdleExit {
		s.log.Info("agent idle, exiting")
		s.shutdown()
	}
}

func (s *server) serve(ctx context.Context) error {
	s.log.Info("agent started")
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(s.opts.ReapInterval)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ctx.Done():
				s.shutdown()
				return
			case <-t.C:
				s.tick()
			}
		}
	}()
	go func() { <-s.stop; _ = s.ln.Close() }()

	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.stop:
			case <-ctx.Done():
			default:
				s.shutdown()
				s.cleanup(done)
				return err
			}
			s.shutdown()
			s.cleanup(done)
			return nil
		}
		select {
		case s.sem <- struct{}{}:
			s.conns.Add(1)
			go func() {
				defer func() { <-s.sem; s.conns.Done() }()
				s.handle(c)
			}()
		default:
			_ = c.Close() // too many connections
		}
	}
}

func (s *server) cleanup(reaper <-chan struct{}) {
	<-reaper
	waited := make(chan struct{})
	go func() { s.conns.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(shutdownWait):
	}
	s.store.wipe()
	// Remove the socket only if it is still the one we created.
	if fi, err := os.Lstat(s.path); err == nil && s.sockFI != nil && os.SameFile(fi, s.sockFI) {
		_ = os.Remove(s.path)
	}
	s.log.Info("agent stopped")
}

// handle serves one connection: peer check first, then request/response
// pairs until the client hangs up, sends garbage, or goes idle.
func (s *server) handle(c net.Conn) {
	defer c.Close()
	if err := (*s.peerCheck.Load())(c); err != nil {
		s.log.Warn("rejected connection from another user")
		return
	}
	for {
		_ = c.SetDeadline(time.Now().Add(connIdle))
		body, err := ReadFrame(c, MaxRequestSize)
		if err != nil {
			if errors.Is(err, ErrMessageTooLarge) || errors.Is(err, ErrBadMessage) {
				_ = WriteFrame(c, encodeResponse(statusBadRequest, nil))
			}
			return
		}
		req, err := ParseRequest(body)
		clear(body)
		if err != nil {
			_ = WriteFrame(c, encodeResponse(statusBadRequest, nil))
			return
		}
		resp, stopAfter := s.dispatch(req)
		clear(req.Key)
		werr := WriteFrame(c, resp)
		clear(resp)
		if stopAfter {
			s.shutdown()
		}
		if werr != nil || stopAfter {
			return
		}
	}
}

func (s *server) dispatch(req Request) (resp []byte, stopAfter bool) {
	switch req.Op {
	case OpPing:
		return encodeResponse(statusOK, nil), false
	case OpUnlock:
		if err := ValidateTTL(req.TTL); err != nil {
			return encodeResponse(statusBadTTL, nil), false
		}
		key, err := crypto.VaultKeyFromBytes(req.Key)
		if err != nil {
			return encodeResponse(statusBadRequest, nil), false
		}
		if err := s.store.put(req.Vault, key, req.TTL); err != nil {
			key.Destroy()
			return encodeResponse(statusFull, nil), false
		}
		return encodeResponse(statusOK, nil), false
	case OpKey:
		key, ok := s.store.get(req.Vault)
		if !ok {
			return encodeResponse(statusLocked, nil), false
		}
		p := encodeKeyPayload(key.Bytes())
		key.Destroy()
		out := encodeResponse(statusOK, p)
		clear(p)
		return out, false
	case OpLock:
		s.store.lock(req.Vault)
		return encodeResponse(statusOK, nil), false
	case OpLockAll:
		s.store.wipe()
		return encodeResponse(statusOK, nil), false
	case OpStatus:
		return encodeResponse(statusOK, encodeStatusPayload(s.store.status())), false
	case OpShutdown:
		s.store.wipe()
		return encodeResponse(statusOK, nil), true
	}
	return encodeResponse(statusBadRequest, nil), false
}
