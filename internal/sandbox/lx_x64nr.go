//go:build (amd64 && (darwin || linux || windows)) || (darwin && arm64)

package sandbox

import "time"

// x86-64 guests: the shared syscall table is keyed by asm-generic numbers, so
// x64Generic maps an x86-64 syscall to its generic form, rewriting the
// arguments of the legacy calls x86-64 has and the generic ABI dropped (open,
// stat, rename, ...) into their *at equivalents. Open flags differ in four
// bits between the ABIs and are swapped here too.

const (
	x64Open         = 2
	x64Stat         = 4
	x64Lstat        = 6
	x64Access       = 21
	x64Pipe         = 22
	x64Dup2         = 33
	x64Rename       = 82
	x64Mkdir        = 83
	x64Rmdir        = 84
	x64Creat        = 85
	x64Link         = 86
	x64Unlink       = 87
	x64Symlink      = 88
	x64Readlink     = 89
	x64Chmod        = 90
	x64Chown        = 92
	x64Lchown       = 94
	x64Getpgrp      = 111
	x64Mknod        = 133
	x64Time         = 201
	x64EpollCreate  = 213
	x64EpollWait    = 232
	x64InotifyInit  = 253
	x64Signalfd     = 282
	x64Eventfd      = 284
	x64Fcntl        = 72
	x64Openat       = 257
	x64Clone        = 56
	x64Fork         = 57
	x64Vfork        = 58
	x64Accept       = 43
	x64Getdents     = 78
	x64ArchPrctl    = 158
	x64Mmap         = 9
	x64Mprotect     = 10
	x64Munmap       = 11
	x64Brk          = 12
	x64Mremap       = 25
	x64ClockGettime = 228

	lxAtNofollow = 0x100

	x64Alarm = 37
	// lxAlarm keys alarm, which arm64 has no number for (its libcs use
	// setitimer).
	lxAlarm = 0x4c43f025
)

func init() { syscalls[lxAlarm] = sysAlarm }

// sysAlarm arms ITIMER_REAL for sec seconds (0 disarms it) and returns the
// seconds that were left, rounded as Linux does: to the nearest, and never 0
// for a timer still running.
func sysAlarm(g *dguest, a [6]uint64) int64 {
	sr := g.sigs()
	sr.mu.Lock()
	defer sr.mu.Unlock()
	pt := g.itimer(0)
	if pt == nil {
		return sErr(lxESRCH)
	}
	old := pt.remaining()
	pt.arm(time.Duration(a[0])*time.Second, 0, a[0] == 0)
	s := int64(old / time.Second)
	if old%time.Second >= time.Second/2 {
		s++
	}
	if s == 0 && old > 0 {
		s = 1
	}
	return s
}

// x64Direct are the x86-64 calls whose generic form takes the same arguments.
var x64Direct = map[uint64]uint64{
	0: 63, 1: 64, 3: 57, 5: 80, 8: 62, 13: 134, 14: 135, 16: 29, 17: 67, 18: 68,
	29: 194, 30: 196, 31: 195, 155: 41, 164: 170, 165: 40, 166: 39, 170: 161, 171: 162, 220: 192, 250: 219, 251: 30, 252: 31,
	19: 65, 20: 66, 24: 124, 26: 227, 27: 232, 28: 233, 32: 23, 35: 101, 36: 102,
	38: 103, 39: 172, 40: 71, 41: 198, 42: 203, 44: 206, 45: 207, 46: 211, 47: 212,
	48: 210, 49: 200, 50: 201, 51: 204, 52: 205, 53: 199, 54: 208, 55: 209,
	59: 221, 60: 93, 61: 260, 62: 129, 63: 160, 64: 190, 65: 193, 66: 191, 67: 197,
	68: 186, 69: 189, 70: 188, 71: 187, 73: 32, 74: 82, 75: 83, 76: 45, 77: 46,
	79: 17, 80: 49, 81: 50, 91: 52, 93: 55, 95: 166, 96: 169, 97: 163, 98: 165,
	99: 179, 100: 153, 101: 117, 102: 174, 103: 116, 104: 176, 105: 146, 106: 144,
	107: 175, 108: 177, 109: 154, 110: 173, 112: 157, 113: 145, 114: 143, 115: 158,
	116: 159, 117: 147, 118: 148, 119: 149, 120: 150, 121: 155, 122: 151, 123: 152,
	124: 156, 125: 90, 126: 91, 127: 136, 128: 137, 129: 138, 130: 133, 131: 132,
	135: 92, 137: 43, 138: 44, 140: 141, 141: 140, 142: 118, 143: 121, 144: 119,
	145: 120, 146: 125, 147: 126, 148: 127, 149: 228, 150: 229, 151: 230, 152: 231,
	157: 167, 160: 164, 161: 51, 162: 81, 186: 178, 187: 213, 188: 5, 189: 6, 190: 7,
	191: 8, 192: 9, 193: 10, 194: 11, 195: 12, 196: 13, 197: 14, 198: 15, 199: 16,
	200: 130, 202: 98, 203: 122, 204: 123, 217: 61, 218: 96, 219: 128, 221: 223,
	222: 107, 223: 110, 224: 108, 225: 109, 226: 111, 227: 112, 228: 113, 229: 114,
	230: 115, 231: 94, 233: 21, 234: 131, 247: 95, 254: 27, 255: 28, 257: 56,
	258: 34, 259: 33, 260: 54, 262: 79, 263: 35, 264: 38, 265: 37, 266: 36, 267: 78,
	268: 53, 269: 48, 270: 72, 271: 73, 272: 97, 273: 99, 274: 100, 275: 76,
	276: 77, 277: 84, 278: 75, 280: 88, 281: 22, 283: 85, 285: 47, 286: 86,
	287: 87, 288: 242, 289: 74, 290: 19, 291: 20, 292: 24, 293: 59, 294: 26,
	295: 69, 296: 70, 297: 240, 298: 241, 299: 243, 302: 261, 305: 266, 306: 267,
	307: 269, 308: 268, 309: 168, 310: 270, 311: 271, 312: 272, 314: 274, 315: 275,
	316: 276, 317: 277, 318: 278, 319: 279, 321: 280, 322: 281, 323: 282, 324: 283,
	325: 284, 326: 285, 327: 286, 328: 287, 329: 288, 330: 289, 331: 290, 332: 291,
	333: 292, 334: 293,
}

// Open flags whose bit differs: x86-64 value, generic value.
var x64OFlags = [4][2]uint64{
	{0x4000, 0x10000}, // O_DIRECT
	{0x8000, 0x20000}, // O_LARGEFILE
	{0x10000, 0x4000}, // O_DIRECTORY
	{0x20000, 0x8000}, // O_NOFOLLOW
}

func swapOFlags(f uint64, toGeneric bool) uint64 {
	from, to := 0, 1
	if !toGeneric {
		from, to = 1, 0
	}
	out := f
	for _, b := range x64OFlags {
		out &^= b[from]
	}
	for _, b := range x64OFlags {
		if f&b[from] != 0 {
			out |= b[to]
		}
	}
	return out
}

// x64Generic maps x86-64 syscall nr with args a to its generic number and
// arguments; ok is false for a call with no generic form here.
func x64Generic(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) {
	const cwd = ^uint64(99) // AT_FDCWD
	switch nr {
	case x64Alarm:
		return lxAlarm, a, true
	case x64Open:
		return lxOpenat, [6]uint64{cwd, a[0], swapOFlags(a[1], true), a[2]}, true
	case x64Openat:
		return lxOpenat, [6]uint64{a[0], a[1], swapOFlags(a[2], true), a[3]}, true
	case x64Creat:
		return lxOpenat, [6]uint64{cwd, a[0], lxOCreat | lxOWronly | lxOTrunc, a[1]}, true
	case x64Stat:
		return lxNewfstatat, [6]uint64{cwd, a[0], a[1], 0}, true
	case x64Lstat:
		return lxNewfstatat, [6]uint64{cwd, a[0], a[1], lxAtNofollow}, true
	case x64Access:
		return lxFaccessat, [6]uint64{cwd, a[0], a[1]}, true
	case x64Dup2:
		const fGetfd = 1
		if a[0] == a[1] {
			return lxFcntl, [6]uint64{a[0], fGetfd}, true
		}
		return lxDup3, [6]uint64{a[0], a[1], 0}, true
	case x64Pipe:
		return lxPipe2, [6]uint64{a[0], 0}, true
	case x64Rename:
		return 38, [6]uint64{cwd, a[0], cwd, a[1]}, true
	case x64Mkdir:
		return lxMkdirat, [6]uint64{cwd, a[0], a[1]}, true
	case x64Rmdir:
		return lxUnlinkat, [6]uint64{cwd, a[0], lxAtRemovedir}, true
	case x64Unlink:
		return lxUnlinkat, [6]uint64{cwd, a[0], 0}, true
	case x64Link:
		return 37, [6]uint64{cwd, a[0], cwd, a[1], 0}, true
	case x64Symlink:
		return 36, [6]uint64{a[0], cwd, a[1]}, true
	case x64Readlink:
		return lxReadlinkat, [6]uint64{cwd, a[0], a[1], a[2]}, true
	case x64Chmod:
		return 53, [6]uint64{cwd, a[0], a[1]}, true
	case x64Chown:
		return 54, [6]uint64{cwd, a[0], a[1], a[2], 0}, true
	case x64Lchown:
		return 54, [6]uint64{cwd, a[0], a[1], a[2], lxAtNofollow}, true
	case x64Mknod:
		return 33, [6]uint64{cwd, a[0], a[1], a[2]}, true
	case x64Getpgrp:
		return 155, [6]uint64{0}, true
	case x64EpollCreate:
		return lxEpollCreate1, [6]uint64{0}, true
	case x64EpollWait:
		return lxEpollPwait, [6]uint64{a[0], a[1], a[2], a[3], 0, 8}, true
	case x64InotifyInit:
		return 26, [6]uint64{0}, true
	case x64Signalfd:
		return 74, [6]uint64{a[0], a[1], a[2], 0}, true
	case x64Eventfd:
		return lxEventfd2, [6]uint64{a[0], 0}, true
	case x64Accept:
		return 242, [6]uint64{a[0], a[1], a[2], 0}, true
	case x64Fcntl:
		const fSetfl = 4
		if a[1] == fSetfl {
			a[2] = swapOFlags(a[2], true)
		}
		return lxFcntl, a, true
	case x64Clone:
		// x86-64 clone(flags, stack, ptid, ctid, tls); generic has tls before ctid.
		return lxClone, [6]uint64{a[0], a[1], a[2], a[4], a[3]}, true
	case x64Fork:
		return lxClone, [6]uint64{17}, true // SIGCHLD
	case x64Vfork:
		return lxClone, [6]uint64{0x4000 | 0x100 | 17}, true // CLONE_VFORK|CLONE_VM|SIGCHLD
	}
	if nr >= 424 {
		return nr, a, true
	}
	g, ok := x64Direct[nr]
	return g, a, ok
}

// x64Result adjusts a generic call's result for an x86-64 guest.
func x64Result(nr uint64, a [6]uint64, r int64) int64 {
	const fGetfl = 3
	switch {
	case nr == x64Fcntl && a[1] == fGetfl && r >= 0:
		return int64(swapOFlags(uint64(r), false))
	case nr == x64Dup2 && a[0] == a[1] && r >= 0:
		return int64(a[0])
	}
	return r
}
