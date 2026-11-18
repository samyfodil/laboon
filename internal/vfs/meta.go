package vfs

import "encoding/binary"

// The override sidecar is a private, append-only binary record stream — no
// reflection, few allocations, and robust to arbitrary path bytes (a Linux path
// may contain anything but NUL and '/'). Each record is:
//
//	uvarint(len(path)) path
//	flags byte            bit0 owner, bit1 mode, bit2 special
//	[owner]   uvarint uid, uvarint gid
//	[mode]    uvarint mode
//	[special] byte kind, uvarint rdev
//
// Paths with no recorded override are omitted, so the common all-root/all-default
// layer writes nothing.

const (
	metaOwner   = 1 << 0
	metaMode    = 1 << 1
	metaSpecial = 1 << 2
)

func EncodeMeta(m map[string]*Override) []byte {
	var b []byte
	var tmp [binary.MaxVarintLen64]byte
	putU := func(v uint64) { b = append(b, tmp[:binary.PutUvarint(tmp[:], v)]...) }
	for p, o := range m {
		if o == nil {
			continue
		}
		var flags byte
		if o.HasOwner {
			flags |= metaOwner
		}
		if o.HasMode {
			flags |= metaMode
		}
		if o.Special {
			flags |= metaSpecial
		}
		if flags == 0 {
			continue
		}
		putU(uint64(len(p)))
		b = append(b, p...)
		b = append(b, flags)
		if o.HasOwner {
			putU(uint64(o.Uid))
			putU(uint64(o.Gid))
		}
		if o.HasMode {
			putU(uint64(o.Mode))
		}
		if o.Special {
			b = append(b, byte(o.Kind))
			putU(o.Rdev)
		}
	}
	return b
}

// DecodeMeta parses the record stream, calling visit for each path. A truncated
// or malformed stream stops parsing without panicking (the sidecar is internal,
// but a half-written file should not crash a reader).
func DecodeMeta(b []byte, visit func(path string, o Override)) {
	take := func() (uint64, bool) {
		v, n := binary.Uvarint(b)
		if n <= 0 {
			return 0, false
		}
		b = b[n:]
		return v, true
	}
	for len(b) > 0 {
		pl, ok := take()
		if !ok || uint64(len(b)) < pl {
			return
		}
		p := string(b[:pl])
		b = b[pl:]
		if len(b) == 0 {
			return
		}
		flags := b[0]
		b = b[1:]
		var o Override
		if flags&metaOwner != 0 {
			uid, ok1 := take()
			gid, ok2 := take()
			if !ok1 || !ok2 {
				return
			}
			o.Uid, o.Gid, o.HasOwner = uint32(uid), uint32(gid), true
		}
		if flags&metaMode != 0 {
			md, ok := take()
			if !ok {
				return
			}
			o.Mode, o.HasMode = uint32(md), true
		}
		if flags&metaSpecial != 0 {
			if len(b) == 0 {
				return
			}
			o.Kind = Kind(b[0])
			b = b[1:]
			rdev, ok := take()
			if !ok {
				return
			}
			o.Rdev, o.Special = rdev, true
		}
		visit(p, o)
	}
}
