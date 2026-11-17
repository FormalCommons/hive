package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

type agent struct {
	cli     string // "claude", "codex" or "pi"
	resume  bool
	prompt  func() (string, error)
	args    []string // extra CLI arguments
	every   time.Duration
	timeout time.Duration
	env     []string // environment of the CLI

	mu       sync.Mutex
	messages []string      // trigger messages for the next run
	queued   int           // total length of messages
	wake     chan struct{} // holds a value while a triggered run is pending
}

// maxQueued limits the total length of queued trigger messages, in bytes.
const maxQueued = 1 << 20

// command returns the CLI invocation for one run. The prompt goes on stdin.
// The CLIs start a new session when there is none to continue, so resume
// needs no bookkeeping of its own. claude and pi take the same flags.
func (a *agent) command() []string {
	if a.cli == "claude" || a.cli == "pi" {
		cmd := []string{a.cli, "-p"}
		if a.resume {
			cmd = append(cmd, "--continue")
		}
		return append(cmd, a.args...)
	}
	cmd := []string{"codex", "exec"}
	if a.resume {
		cmd = append(cmd, "resume", "--last")
	}
	return append(append(cmd, a.args...), "-")
}

// trigger asks for a run as soon as the current one, if any, is over.
// Triggers that arrive before that run starts are merged into it. It reports
// false if the message does not fit in the queue; the run is asked for either
// way, so that a full queue is emptied.
func (a *agent) trigger(message string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	if a.queued+len(message) > maxQueued {
		return false
	}
	if message != "" {
		a.messages = append(a.messages, message)
		a.queued += len(message)
	}
	return true
}

// take returns the queued trigger messages and clears the pending trigger,
// since the run about to start covers it.
func (a *agent) take() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	select {
	case <-a.wake:
	default:
	}
	m := a.messages
	a.messages, a.queued = nil, 0
	return m
}

// loop runs the CLI on the timer and on triggers, one run at a time, until
// ctx is cancelled.
func (a *agent) loop(ctx context.Context) {
	var timer <-chan time.Time
	if a.every > 0 {
		timer = time.After(0)
	}
	for n := 1; ; n++ {
		reason := "timer"
		select {
		case <-ctx.Done():
			return
		case <-timer:
		case <-a.wake:
			reason = "trigger"
		}
		if ctx.Err() != nil {
			return
		}
		a.run(ctx, n, reason)
		if a.every > 0 {
			timer = time.After(a.every)
		}
	}
}

// Exit statuses of a run that did not end by itself, as timeout(1) and the
// shell report them.
const (
	statusTimedOut = 124
	statusStopped  = 128 + int(syscall.SIGTERM)
)

// run runs the CLI once. It returns the CLI's exit status, as the shell
// reports it; statusTimedOut or statusStopped if the run was cut short; or
// 1 if it did not start.
func (a *agent) run(ctx context.Context, n int, reason string) int {
	prompt, err := a.prompt()
	if err != nil {
		log.Printf("run %d skipped: %v", n, err)
		return 1
	}
	messages := a.take()
	prompt = strings.Join(nonEmpty(append([]string{strings.TrimSpace(prompt)}, messages...)), "\n\n")
	if prompt == "" {
		log.Printf("run %d: empty prompt, skipped", n)
		return 1
	}
	runCtx := ctx
	if a.timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}

	args := a.command()
	cmd := exec.CommandContext(runCtx, args[0], args[1:]...)
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = a.env
	// The CLI starts processes of its own, so it runs in its own process
	// group, and the whole group is stopped together.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); !errors.Is(err, syscall.ESRCH) {
			return err
		}
		return os.ErrProcessDone
	}
	cmd.WaitDelay = 10 * time.Second

	log.Printf("run %d started (%s, %d trigger messages)", n, reason, len(messages))
	start := time.Now()
	err = cmd.Run()
	if cmd.Process != nil {
		// Stop whatever the run left in its process group.
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	status, result := 0, "succeeded"
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		status, result = statusStopped, "stopped"
	case runCtx.Err() != nil:
		status, result = statusTimedOut, "timed out"
	case errors.As(err, &exit):
		status, result = exitStatus(exit), "failed: "+err.Error()
	case err != nil:
		status, result = 1, "failed: "+err.Error()
	}
	log.Printf("run %d %s after %s", n, result, time.Since(start).Round(time.Second))
	return status
}

// exitStatus reports a process killed by a signal as the shell does, as
// 128 plus the signal number, where ExitCode reports -1.
func exitStatus(e *exec.ExitError) int {
	if ws, ok := e.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return e.ExitCode()
}

func nonEmpty(s []string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// handler serves the trigger API. If token is set, POST /trigger requires
// "Authorization: Bearer <token>".
func (a *agent) handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {})
	mux.HandleFunc("POST /trigger", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		ok := len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") &&
			subtle.ConstantTimeCompare([]byte(auth[7:]), []byte(token)) == 1
		if token != "" && !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxQueued))
		if err != nil {
			http.Error(w, "body unreadable or larger than 1 MiB", http.StatusBadRequest)
			return
		}
		if !a.trigger(strings.TrimSpace(string(body))) {
			http.Error(w, "too many queued trigger messages; retry after the next run", http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	return mux
}
