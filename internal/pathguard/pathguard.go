// Package pathguard contains small filesystem helpers for controller-owned
// paths. It rejects symlink components rather than wandering into an unrelated
// tree.
package pathguard

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// ValidateNoSymlinkComponents checks every existing component of path,
// including the final component. Missing final components are allowed so the
// caller can create them after the check. A missing parent stops the walk,
// because descendants cannot exist below it yet.
func ValidateNoSymlinkComponents(path string) error {
	if path == "" {
		return errors.New("path is required")
	}
	absolute, err := canonicalAbsolute(path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	current := string(filepath.Separator)
	for _, component := range splitPath(absolute) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path component %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink path component %s", current)
		}
	}
	return nil
}

// ReadFile opens the final file relative to a descriptor-walked parent. Every
// directory and the final file are opened with O_NOFOLLOW, so a path swap
// after validation cannot redirect the read through a symlink.
func ReadFile(path string) ([]byte, error) {
	return ReadFileLimited(path, 0)
}

// ReadFileLimited reads a descriptor-walked file while enforcing an optional
// maximum size. A limit prevents untrusted generated inputs from being
// materialised without bound.
func ReadFileLimited(path string, maxBytes int64) ([]byte, error) {
	if maxBytes < 0 {
		return nil, errors.New("maximum file size cannot be negative")
	}
	parent, _, name, err := openParent(path, false, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open file descriptor failed")
	}
	defer file.Close()
	reader := io.Reader(file)
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %s exceeds maximum size of %d bytes", path, maxBytes)
	}
	return data, nil
}

// ReadDir returns directory entries from a descriptor-walked directory. The
// returned entries are intended for name/type inspection followed by ReadFile
// or another descriptor-relative operation.
func ReadDir(path string) ([]os.DirEntry, error) {
	fd, _, err := openDirectory(path, false, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open directory descriptor failed")
	}
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return nil, &os.PathError{Op: "read directory", Path: path, Err: err}
	}
	return entries, nil
}

// WriteFile atomically replaces a regular file using descriptor-relative
// open/rename operations. Existing path components cannot be redirected by a
// concurrent symlink swap.
func WriteFile(path string, data []byte, mode os.FileMode) error {
	return WriteFileWithParentMode(path, data, mode, 0700)
}

func WriteFileWithParentMode(path string, data []byte, mode, parentMode os.FileMode) error {
	parent, _, name, err := openParent(path, true, parentMode)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	temporary, err := temporaryEntry(parent, ".boetticher-")
	if err != nil {
		return &os.PathError{Op: "create", Path: path, Err: err}
	}
	defer func() { _ = unix.Unlinkat(parent, temporary.name, 0) }()
	file := os.NewFile(uintptr(temporary.fd), path)
	if file == nil {
		_ = unix.Close(temporary.fd)
		return errors.New("create file descriptor failed")
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	written, err := file.Write(data)
	if err != nil {
		_ = file.Close()
		return &os.PathError{Op: "write", Path: path, Err: err}
	}
	if written != len(data) {
		_ = file.Close()
		return &os.PathError{Op: "write", Path: path, Err: io.ErrShortWrite}
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return &os.PathError{Op: "sync", Path: path, Err: err}
	}
	if err := file.Close(); err != nil {
		return &os.PathError{Op: "close", Path: path, Err: err}
	}
	if err := rejectSymlinkAt(parent, name); err != nil {
		return err
	}
	if err := unix.Renameat(parent, temporary.name, parent, name); err != nil {
		return &os.PathError{Op: "rename", Path: path, Err: err}
	}
	temporary.name = ""
	return nil
}

// WriteFileFrom atomically streams a bounded file beneath a descriptor-walked
// parent. The parent descriptor remains open through temporary creation and
// rename, closing the validation-to-use race present in string-path writes.
func WriteFileFrom(path string, reader io.Reader, mode os.FileMode, maxBytes int64) (int64, error) {
	if reader == nil {
		return 0, errors.New("file source is required")
	}
	if maxBytes <= 0 {
		return 0, errors.New("maximum file size must be positive")
	}
	parent, _, name, err := openParent(path, false, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(parent)
	temporary, err := temporaryEntry(parent, ".boetticher-")
	if err != nil {
		return 0, &os.PathError{Op: "create", Path: path, Err: err}
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = unix.Unlinkat(parent, temporary.name, 0)
		}
	}()
	file := os.NewFile(uintptr(temporary.fd), path)
	if file == nil {
		_ = unix.Close(temporary.fd)
		return 0, errors.New("create file descriptor failed")
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return 0, &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	written, err := io.Copy(file, io.LimitReader(reader, maxBytes+1))
	if err != nil {
		_ = file.Close()
		return written, &os.PathError{Op: "write", Path: path, Err: err}
	}
	if written > maxBytes {
		_ = file.Close()
		return written, fmt.Errorf("file %s exceeds maximum size of %d bytes", path, maxBytes)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return written, &os.PathError{Op: "sync", Path: path, Err: err}
	}
	if err := file.Close(); err != nil {
		return written, &os.PathError{Op: "close", Path: path, Err: err}
	}
	if err := rejectSymlinkAt(parent, name); err != nil {
		return written, err
	}
	if err := unix.Renameat(parent, temporary.name, parent, name); err != nil {
		return written, &os.PathError{Op: "rename", Path: path, Err: err}
	}
	removeTemporary = false
	return written, nil
}

// MkdirAll creates a path by opening each component relative to the previous
// directory descriptor with O_NOFOLLOW.
func MkdirAll(path string, mode os.FileMode) error {
	fd, _, err := openDirectory(path, true, mode)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// MkdirTemp creates a temporary directory relative to a descriptor-walked
// parent. It returns the canonical path used for subsequent descriptor-safe
// operations.
func MkdirTemp(parent, prefix string, mode os.FileMode) (string, error) {
	fd, canonicalParent, err := openDirectory(parent, false, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	if strings.ContainsAny(prefix, `/\\`) {
		return "", errors.New("temporary directory prefix must be a name")
	}
	for attempt := 0; attempt < 100; attempt++ {
		name, err := randomName(prefix)
		if err != nil {
			return "", err
		}
		err = unix.Mkdirat(fd, name, uint32(mode.Perm()))
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", &os.PathError{Op: "mkdir", Path: filepath.Join(parent, name), Err: err}
		}
		return filepath.Join(canonicalParent, name), nil
	}
	return "", errors.New("could not create a unique temporary directory")
}

// RemoveAll removes a path without following symlinks. The recursive walk is
// performed through opened directory descriptors, and a symlink encountered at
// any point is rejected rather than traversed or deleted.
func RemoveAll(path string) error {
	parent, _, name, err := openParent(path, false, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	return removeEntry(parent, name, path)
}

// Rename atomically renames two paths after opening both parents without
// following symlinks. The final source and destination names are checked with
// AT_SYMLINK_NOFOLLOW, and rename itself never dereferences them.
func Rename(oldPath, newPath string) error {
	oldParent, _, oldName, err := openParent(oldPath, false, 0)
	if err != nil {
		return err
	}
	defer unix.Close(oldParent)
	newParent, _, newName, err := openParent(newPath, false, 0)
	if err != nil {
		return err
	}
	defer unix.Close(newParent)
	if err := rejectSymlinkAt(oldParent, oldName); err != nil {
		return err
	}
	if err := rejectSymlinkAt(newParent, newName); err != nil {
		return err
	}
	if err := unix.Renameat(oldParent, oldName, newParent, newName); err != nil {
		return &os.PathError{Op: "rename", Path: newPath, Err: err}
	}
	return nil
}

type temporaryFile struct {
	fd   int
	name string
}

func temporaryEntry(parent int, prefix string) (temporaryFile, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name, err := randomName(prefix)
		if err != nil {
			return temporaryFile{}, err
		}
		fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return temporaryFile{}, err
		}
		return temporaryFile{fd: fd, name: name}, nil
	}
	return temporaryFile{}, errors.New("could not create a unique temporary file")
}

func randomName(prefix string) (string, error) {
	var random [12]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(random[:]), nil
}

func removeEntry(parent int, name, path string) error {
	var stat unix.Stat_t
	if err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return &os.PathError{Op: "lstat", Path: path, Err: err}
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("refusing to remove symlink path %s", path)
	}
	directory, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		file := os.NewFile(uintptr(directory), path)
		if file == nil {
			_ = unix.Close(directory)
			return errors.New("open directory descriptor failed")
		}
		entries, readErr := file.ReadDir(-1)
		if readErr == nil {
			for _, entry := range entries {
				if err := removeEntry(directory, entry.Name(), filepath.Join(path, entry.Name())); err != nil {
					readErr = err
					break
				}
			}
		}
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := unix.Unlinkat(parent, name, unix.AT_REMOVEDIR); err != nil {
			return &os.PathError{Op: "rmdir", Path: path, Err: err}
		}
		return nil
	}
	if errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("refusing to remove symlink path %s", path)
	}
	if !errors.Is(err, unix.ENOTDIR) {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return &os.PathError{Op: "open", Path: path, Err: err}
	}
	if err := unix.Unlinkat(parent, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "unlink", Path: path, Err: err}
	}
	return nil
}

func rejectSymlinkAt(parent int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(parent, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("refusing symlink path component %s", name)
	}
	return nil
}

func openParent(path string, create bool, mode os.FileMode) (int, string, string, error) {
	absolute, err := canonicalAbsolute(path)
	if err != nil {
		return 0, "", "", err
	}
	name := filepath.Base(absolute)
	if name == string(filepath.Separator) || name == "." || name == ".." {
		return 0, "", "", errors.New("path must name a file or directory entry")
	}
	parent := filepath.Dir(absolute)
	fd, canonicalParent, err := openDirectory(parent, create, mode)
	if err != nil {
		return 0, "", "", err
	}
	return fd, canonicalParent, name, nil
}

func openDirectory(path string, create bool, mode os.FileMode) (int, string, error) {
	absolute, err := canonicalAbsolute(path)
	if err != nil {
		return 0, "", err
	}
	current, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, "", err
	}
	for _, component := range splitPath(absolute) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(current, component, uint32(mode.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(current)
				return 0, "", &os.PathError{Op: "mkdir", Path: filepath.Join(absolute, component), Err: mkdirErr}
			}
			next, openErr = unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(current)
			return 0, "", &os.PathError{Op: "open directory", Path: absolute, Err: openErr}
		}
		_ = unix.Close(current)
		current = next
	}
	return current, absolute, nil
}

func canonicalAbsolute(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute = filepath.Clean(absolute)
	if runtime.GOOS == "darwin" {
		// /var and /tmp are stable system aliases on macOS. Use their real
		// roots so descriptor walking can reject all user-controlled links.
		if absolute == "/var" || strings.HasPrefix(absolute, "/var/") || absolute == "/tmp" || strings.HasPrefix(absolute, "/tmp/") {
			absolute = "/private" + absolute
		}
	}
	return absolute, nil
}

func splitPath(path string) []string {
	result := make([]string, 0)
	for path != "" {
		component := filepath.Base(path)
		if component == string(filepath.Separator) || component == "." {
			break
		}
		result = append(result, component)
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}
	return result
}
