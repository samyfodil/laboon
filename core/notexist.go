package core

import (
	"errors"
	"io/fs"
)

// NotExist is the standard not-found error a FileSystem returns from Lookup.
func NotExist(op, p string) error { return &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist} }

// MaybeNotExist is the not-found error of a lookup that failed for another
// reason, cause (a host lstat refused, say): the guest sees the name as
// missing, as it always did, but it may be there, so no cache keeps the miss.
func MaybeNotExist(op, p string, cause error) error {
	return &fs.PathError{Op: op, Path: p, Err: &doubtful{cause}}
}

type doubtful struct{ cause error }

func (d *doubtful) Error() string { return fs.ErrNotExist.Error() + " (" + d.cause.Error() + ")" }

// Is makes a doubtful miss a not-exist; it does not unwrap to its cause, so the
// guest's errno stays ENOENT.
func (d *doubtful) Is(target error) bool { return target == fs.ErrNotExist }

// DefinitelyNotExist reports whether err is a miss a cache may keep: the name
// is absent, not merely unreadable.
func DefinitelyNotExist(err error) bool {
	var d *doubtful
	return errors.Is(err, fs.ErrNotExist) && !errors.As(err, &d)
}
