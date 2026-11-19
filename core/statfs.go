package core

// StatFS holds a filesystem's statfs counters, in the units statfs(2) reports.
type StatFS struct {
	Bsize, Blocks, Bfree, Bavail, Files, Ffree uint64
	Fsid                                       [2]uint32
	Type                                       uint64 // the backing filesystem's f_type (0 if unknown)
}

// StatFSer is the optional capability of a FileSystem that reports the statfs of
// the filesystem backing one of its nodes: a backend doing host I/O answers from
// the host, a union forwards to the layer that owns the node. A FileSystem
// without it (a purely synthetic one) has no meaningful statfs of its own.
type StatFSer interface {
	StatFS(n Node) (StatFS, error)
}
