package core

import "io/fs"

// NotExist is the standard not-found error a FileSystem returns from Lookup.
func NotExist(op, p string) error { return &fs.PathError{Op: op, Path: p, Err: fs.ErrNotExist} }
