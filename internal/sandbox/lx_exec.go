//go:build darwin || linux || windows

package sandbox

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path"
	"strings"
)

// execve's host-neutral half: resolving the program (and its #! chain), the
// argument vectors, and retiring the process's other threads.

// execTarget is a resolved execve.
type execTarget struct {
	gp     string   // the program's guest path
	src    execSrc  // the ELF that runs, as the host reads it
	prefix []string // argv a #! chain adds
	skip   uint64   // guest argv entries the prefix replaces
	elf    string   // the guest path of the ELF that runs, when it was found by path
	from   *dfile   // the descriptor the ELF runs from (AT_EMPTY_PATH, proc-fd), referenced until drop or exePin
}

// drop releases the descriptor t holds, if exePin has not taken it.
func (t *execTarget) drop() {
	if t.from != nil {
		t.from.unref()
		t.from = nil
	}
}

// exePin is what /proc/<pid>/exe holds of the program an exec ran: the
// descriptor's file when it ran one (its name may be gone), else the file at
// the ELF's path, opened for reading. nil leaves the link path-based.
func (g *dguest) exePin(t *execTarget) *dfile {
	if d := t.from; d != nil {
		t.from = nil
		if p := d.pinned; p != nil {
			p.refs.Add(1)
			d.unref()
			d = p
		}
		if d.vf == nil {
			d.unref()
			return nil
		}
		return d
	}
	loc, err := g.vns().Resolve(t.elf, true)
	if err != nil {
		return nil
	}
	return g.pinOpen(t.elf, loc.Node)
}

const maxArgStrlen = 32 * 4096 // Linux's MAX_ARG_STRLEN

const (
	maxInterpDepth = 4 // nested #! levels Linux follows before ELOOP
	binprmBuf      = 256
)

// hasArgv0 reports whether the guest's argv has at least one entry.
func (g *dguest) hasArgv0(argvAddr uint64) bool {
	if argvAddr == 0 {
		return false
	}
	b, err := g.readMem(argvAddr, 8)
	return err == nil && le64(b) != 0
}

// checkELF accepts a 64-bit little-endian executable or PIE for the guest's
// machine.
func checkELF(h []byte, want elf.Machine) lxErrno {
	if len(h) < 64 || !bytes.HasPrefix(h, []byte(elf.ELFMAG)) ||
		elf.Class(h[elf.EI_CLASS]) != elf.ELFCLASS64 || elf.Data(h[elf.EI_DATA]) != elf.ELFDATA2LSB {
		return lxENOEXEC
	}
	typ := elf.Type(uint16(h[16]) | uint16(h[17])<<8)
	mach := elf.Machine(uint16(h[18]) | uint16(h[19])<<8)
	if mach != want || typ != elf.ET_EXEC && typ != elf.ET_DYN {
		return lxENOEXEC
	}
	return 0
}

// readArgv reads a NULL-terminated guest string vector (argv, envp); a NULL
// vector is empty. Each peek stays within one page: a peek that ran into an
// unmapped page would fault the stub, not fail.
func (g *dguest) readArgv(addr uint64) ([]string, lxErrno) {
	var out []string
	if addr == 0 {
		return nil, 0
	}
	for a := addr; ; {
		n := min(uint64(scratchLen), strPage-(a&(strPage-1))) &^ 7
		if n == 0 {
			n = 8
		}
		b, err := g.readMem(a, int(n))
		if err != nil {
			return nil, lxEFAULT
		}
		for k := 0; k+8 <= len(b); k += 8 {
			p := le64(b[k:])
			if p == 0 {
				return out, 0
			}
			s, err := g.readCStrN(p, maxArgStrlen)
			if err != nil {
				return nil, lxEFAULT
			}
			out = append(out, s)
		}
		a += n
	}
}

// readCStrN is readCStr with a caller-chosen bound.
func (g *dguest) readCStrN(addr uint64, max int) (string, error) {
	var b []byte
	for len(b) < max {
		a := addr + uint64(len(b))
		chunk := uint64(scratchLen)
		if toPage := strPage - (a & (strPage - 1)); toPage < chunk {
			chunk = toPage
		}
		buf := g.ioBuf(int(chunk))
		if err := g.getBuf(a, buf); err != nil {
			return "", err
		}
		if i := indexByte(buf, 0); i >= 0 {
			return string(append(b, buf[:i]...)), nil
		}
		b = append(b, buf...)
	}
	return string(b), nil
}

// takeOverGroup retires the process's other threads at an exec. A non-leader
// thread that execs becomes the leader, with the process's pid as its tid, as
// on Linux; the old leader's serve loop then ends without ending the process.
// It returns the retired threads' channels: where they share the exec's stub,
// their host threads must be gone before its address space is cleared. The
// thread's robust list goes with its old image, as Linux drops it at exec.
func (g *dguest) takeOverGroup() []*hostChan {
	g.robust[0].Store(0)
	g.robust[1].Store(0)
	type wake struct {
		tid  int
		ch   *hostChan
		stop chan struct{}
	}
	var wakes []wake
	fs := g.dfs
	fs.mu.Lock()
	ps := g.ps
	for tid, p := range fs.procs {
		if p.ps == ps && tid != g.pid {
			wakes = append(wakes, wake{tid, p.ch, p.stop})
		}
	}
	// Linux threads share a process stop channel. Retiring the old image's
	// siblings closes it, so the exec survivor must get a fresh one first.
	// Otherwise later blocking calls (notably vfork) see a dead process even
	// though this thread is running the new image. Other hosts may already
	// have replaced the channel when they moved exec into a new stub.
	if me := fs.procs[g.pid]; me != nil && me.stop != nil {
		for _, w := range wakes {
			if w.stop == me.stop {
				me.stop = make(chan struct{})
				g.ch.stop = me.stop
				break
			}
		}
	}
	old := g.pid
	if g.isThread {
		me := fs.procs[g.pid]
		delete(fs.procs, g.pid)
		delete(ps.comm, g.pid)
		ps.ns.deregister(g.pid) // the thread's tid is gone; the process keeps its tgid
		fs.procs[ps.tgid] = me
		g.pid, g.isThread = ps.tgid, false
	}
	if fs.tracing != nil {
		fs.tracing.takeOver(g, old)
	}
	fs.mu.Unlock()
	chs := make([]*hostChan, 0, len(wakes))
	for _, w := range wakes {
		fs.retire(w.tid, w.stop, w.ch)
		if w.ch != nil {
			chs = append(chs, w.ch)
		}
	}
	fs.sigTakeOver(old, ps.tgid)
	return chs
}

// execDirSuffix fails an exec path that ends in "/", "/." or "/..": its last
// component must then be a directory (ENOTDIR otherwise), and a directory is
// not executable.
func (g *dguest) execDirSuffix(dirfd int64, prog string) lxErrno {
	base := prog
	for {
		switch {
		case len(base) > 1 && strings.HasSuffix(base, "/"):
			base = base[:len(base)-1]
		case strings.HasSuffix(base, "/."):
			base = base[:len(base)-2]
		case strings.HasSuffix(base, "/.."):
			base = base[:len(base)-3]
		default:
			if base == prog {
				return 0
			}
			if base == "" {
				base = "/"
			}
			gp, e := g.walkAt(dirfd, base, true)
			if e != 0 {
				return e
			}
			fi, e := g.lstatGuest(gp)
			if e != 0 {
				return e
			}
			if !fi.IsDir() {
				return lxENOTDIR
			}
			return lxEACCES
		}
	}
}

// descExec yields the readable ELF source for execing the open file d names —
// an execveat(AT_EMPTY_PATH) or a /proc/<pid>/fd/<n>. It checks the file is
// regular and executable by the descriptor's own inode rather than by a path
// that may already be gone (crun bind-mounts its binary, O_PATHs it, then
// unmounts and unlinks the name before execing the fd). own reports whether the
// loader must close the returned file after dup'ing it.
func (g *dguest) descExec(d *dfile) (rf *os.File, own bool, e lxErrno) {
	if d.pinned != nil {
		return g.descExec(d.pinned)
	}
	if d.isDir || d.ev != nil || d.ep != nil || d.sk != nil || d.sf != nil || d.tfd != nil || d.pid != 0 {
		return nil, false, lxEACCES
	}
	switch {
	case d.pathFD != nil: // O_PATH: re-open the pinned inode for reading
		f, er := reopenReadable(d.pathFD)
		if er != 0 {
			return nil, false, er
		}
		rf, own = f, true
	case d.f != nil:
		rf = d.f
	case d.vf != nil: // a host regular file: the loader gets a descriptor of its own
		f, ok := hostDupOf(d.vf, d.gp)
		if !ok {
			return nil, false, lxEACCES
		}
		rf, own = f, true
	default:
		return nil, false, lxEACCES
	}
	fi, serr := rf.Stat()
	switch {
	case serr != nil:
		e = osErrno(serr)
	case !fi.Mode().IsRegular():
		e = lxEACCES
	default:
		if c, ok := g.fsCred(); ok && !g.dacFile(&c, fi, mayExec) {
			e = lxEACCES
		}
	}
	if e != 0 {
		if own {
			rf.Close()
		}
		return nil, false, e
	}
	return rf, own, 0
}

// execTarget resolves an execve's program within the root, following #!
// scripts to their interpreter: argv becomes prefix ++ guest argv[skip:].
// src is the host's handle on the ELF that finally runs (execSource).
func (g *dguest) execTarget(dirfd int64, pathAddr, argvAddr uint64, flags int64) (execTarget, lxErrno) {
	var t execTarget
	fail := func(e lxErrno) (execTarget, lxErrno) { return t, e }
	if flags&^(lxAtSymlinkNofollow|lxAtEmptyPath) != 0 {
		return fail(lxEINVAL)
	}
	prog, rerr := g.readCStr(pathAddr)
	if rerr != nil {
		return fail(lxEFAULT)
	}
	var gp, filename string
	var fexec *os.File // AT_EMPTY_PATH / proc-fd: run this open file, not whatever its path names now
	var fexecOwn, fexecChecked bool
	var from *dfile
	switch {
	case prog == "" && flags&lxAtEmptyPath == 0:
		return fail(lxENOENT)
	case prog == "":
		if dirfd == lxAtFdcwd {
			return fail(lxEACCES)
		}
		d, ok := g.ft.get(int(dirfd))
		if !ok {
			return fail(lxEBADF)
		}
		rf, own, e := g.descExec(d)
		if e != 0 {
			return fail(e)
		}
		gp, filename, fexec, fexecOwn, fexecChecked, from = d.gp, fmt.Sprintf("/dev/fd/%d", dirfd), rf, own, true, d
	default:
		if len(prog) >= 4096 {
			return fail(lxENAMETOOLONG)
		}
		if e := g.execDirSuffix(dirfd, prog); e != 0 {
			return fail(e)
		}
		lp, e := g.walkAt(dirfd, prog, false)
		if e != 0 {
			return fail(e)
		}
		// A /proc/<pid>/fd/<n> (or /dev/fd/<n>) that names an open file with no
		// path of its own — a memfd or an unlinked file — is run from the
		// descriptor, as execve of that magic link does on Linux. This is how
		// laboon's own stub is launched (memfd + exec /proc/self/fd/N), so it
		// lets a guest run laboon under laboon.
		if loc, rerr := g.vns().Resolve(lp, false); rerr == nil {
			if d := fdOfPseudo(loc.Node); d != nil {
				rf, own, e := g.descExec(d)
				if e != 0 {
					return fail(e)
				}
				gp, filename, fexec, fexecOwn, fexecChecked, from = d.gp, prog, rf, own, true, d
				break
			}
		}
		if flags&lxAtSymlinkNofollow != 0 {
			if _, isLink, _ := g.linkTarget(lp); isLink {
				return fail(lxELOOP)
			}
		}
		if gp, e = g.resolve(lp, true); e != 0 {
			return fail(e)
		}
		filename = prog
		if dirfd != lxAtFdcwd && !path.IsAbs(prog) {
			filename = fmt.Sprintf("/dev/fd/%d/%s", dirfd, prog)
		}
	}

	var prefix []string
	skip := uint64(0)
	argc0 := g.hasArgv0(argvAddr)
	cur := gp
	for depth := 0; ; depth++ {
		var f *os.File
		if depth == 0 {
			f = fexec
		}
		s, e := g.execSource(cur, f)
		if e != 0 {
			return fail(e)
		}
		if !(depth == 0 && fexecChecked) {
			// A descriptor source (AT_EMPTY_PATH / proc-fd) was already checked
			// executable by its own inode; its path may be gone, so do not
			// re-check it here.
			if e := g.dacCheck(cur, mayExec); e != 0 {
				return fail(e)
			}
		}
		head, e := g.execSrcHead(s)
		if e != 0 {
			return fail(e)
		}
		if !bytes.HasPrefix(head, []byte("#!")) {
			if e := checkELF(head, elfMach(g)); e != 0 {
				return fail(e)
			}
			t.src, t.elf = s, cur
			if depth == 0 {
				markSrcOwn(&t.src, fexecOwn) // the loader closes a reopened handle after dup
				if from != nil {
					from.refs.Add(1)
					t.from = from
				}
			}
			break
		}
		if depth == 0 && fexecOwn {
			fexec.Close() // a #! interpreter is resolved by path; the reopened handle is done
			fexecOwn = false
		}
		if depth >= maxInterpDepth {
			return fail(lxELOOP)
		}
		line := head[2:]
		if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		interp, arg := splitShebang(string(line))
		if interp == "" {
			return fail(lxENOEXEC)
		}
		np := []string{interp}
		if arg != "" {
			np = append(np, arg)
		}
		np = append(np, filename)
		switch {
		case len(prefix) > 0:
			np = append(np, prefix[1:]...)
		case argc0:
			skip = 1
		}
		prefix = np
		filename = interp
		if cur, e = g.walkAt(lxAtFdcwd, interp, true); e != 0 {
			return fail(e)
		}
	}
	t.gp, t.prefix, t.skip = gp, prefix, skip
	return t, 0
}
