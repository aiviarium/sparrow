package testutil

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Proc is a child process a test runs as a separate program, such as a
// node that dials in to a hub or waits to be dialed. Its standard error is
// kept (Log) and printed when the test fails; its standard output is read
// line by line (Line).
type Proc struct {
	Name  string
	Cmd   *exec.Cmd
	mu    sync.Mutex
	log   bytes.Buffer
	lines chan string
	done  chan struct{}
	err   error
}

type procLog struct{ p *Proc }

func (w procLog) Write(b []byte) (int, error) {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return w.p.log.Write(b)
}

// StartProc starts bin with args. The process is stopped (Stop) when the
// test ends.
func StartProc(t testing.TB, name, bin string, args ...string) *Proc {
	t.Helper()
	p := &Proc{Name: name, Cmd: exec.Command(bin, args...), lines: make(chan string, 64), done: make(chan struct{})}
	p.Cmd.Stderr = procLog{p}
	out, err := p.Cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			select {
			case p.lines <- sc.Text():
			default: // nobody reads them
			}
		}
		_, _ = io.Copy(io.Discard, out)
		// Wait only after standard output is drained (os/exec rule).
		err := p.Cmd.Wait()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	t.Cleanup(func() {
		_ = p.Stop()
		if t.Failed() {
			t.Logf("%s log:\n%s", name, p.Log())
		}
	})
	return p
}

// Log returns what the process wrote to standard error so far.
func (p *Proc) Log() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log.String()
}

// Line returns the next line of standard output.
func (p *Proc) Line(timeout time.Duration) (string, error) {
	select {
	case l := <-p.lines:
		return l, nil
	case <-p.done:
		select {
		case l := <-p.lines:
			return l, nil
		default:
		}
		return "", errors.New(p.Name + " exited")
	case <-time.After(timeout):
		return "", errors.New(p.Name + ": no output line in time")
	}
}

// Done is closed when the process has exited.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Err is the process's exit error, once Done is closed.
func (p *Proc) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// Stop sends SIGTERM and waits up to 10 s for the process to exit, then
// kills it. It returns the exit error.
func (p *Proc) Stop() error {
	select {
	case <-p.done:
		return p.Err()
	default:
	}
	_ = p.Cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		return p.Err()
	case <-time.After(10 * time.Second):
		p.Kill()
		return errors.New(p.Name + " did not exit after SIGTERM and was killed")
	}
}

// Kill kills the process at once (a crash, as far as its peers can tell)
// and waits for it.
func (p *Proc) Kill() {
	_ = p.Cmd.Process.Kill()
	<-p.done
}
