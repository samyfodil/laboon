//go:build !unix

package core

import "os"

func FileID(fi os.FileInfo) (id uint64, nlink uint64, ok bool) { return 0, 0, false }

func StatID(fi os.FileInfo) (NodeID, bool) { return NodeID{}, false }
