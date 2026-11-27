package admin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Store is a data directory whose files are written atomically: each write
// goes to a temporary file in the same directory, is synced, and is renamed
// over the old file, and the directory is synced (reference-server note,
// section 2). A crash leaves either the old or the new content; leftover
// temporary files are removed when the store is opened.
type Store struct {
	dir string
	mu  sync.Mutex
	// CrashAfterWrite, for tests, is called after a temporary file is
	// written and before it is renamed; an error aborts the write there,
	// as a crash would.
	CrashAfterWrite func(name string) error
}

const tmpSuffix = ".tmp"

// OpenStore opens (creating it if needed) a data directory.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	// Remove temporary files a crash may have left behind.
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, tmpSuffix) {
			_ = os.Remove(p)
		}
		return nil
	})
	return s, nil
}

// Dir returns the directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path(name string) (string, error) {
	if name == "" || strings.Contains(name, "..") || filepath.IsAbs(name) || strings.HasSuffix(name, tmpSuffix) {
		return "", fmt.Errorf("admin: bad store file name %q", name)
	}
	return filepath.Join(s.dir, filepath.FromSlash(name)), nil
}

// Write replaces a file atomically. name may contain one directory level
// ("secrets/x").
func (s *Store) Write(name string, data []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(p)+".*"+tmpSuffix)
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if s.CrashAfterWrite != nil {
		if err := s.CrashAfterWrite(name); err != nil {
			ok = true // a crash leaves the temporary file behind
			return err
		}
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// Read returns a file's content, or an error satisfying
// errors.Is(err, os.ErrNotExist).
func (s *Store) Read(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Remove deletes a file; a missing file is not an error.
func (s *Store) Remove(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(p))
}

// List returns the names of the files in a subdirectory, sorted.
func (s *Store) List(sub string) ([]string, error) {
	p, err := s.path(sub)
	if err != nil {
		return nil, err
	}
	es, err := os.ReadDir(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), tmpSuffix) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
