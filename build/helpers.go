package build

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/samyfodil/laboon/internal/oci"
	"github.com/samyfodil/laboon/internal/vfs"
	"github.com/samyfodil/laboon/internal/vfs/hostfs"
)

// baseConfig seeds the image config from the base image's.
func baseConfig(c oci.Config) v1.Config {
	return v1.Config{
		Env:        append([]string(nil), c.Env...),
		Cmd:        append([]string(nil), c.Cmd...),
		Entrypoint: append([]string(nil), c.Entrypoint...),
		WorkingDir: c.WorkingDir,
		User:       c.User,
	}
}

// shellOrExec is the argv for a CMD/ENTRYPOINT: the JSON array as given, or the
// shell form wrapped in /bin/sh -c.
func shellOrExec(in Instruction) []string {
	if in.Exec {
		return append([]string(nil), in.Args...)
	}
	if len(in.Args) == 0 {
		return nil
	}
	return []string{"/bin/sh", "-c", in.Args[0]}
}

// pairs parses ENV/LABEL arguments into key/value pairs, handling both the
// "KEY=VALUE ..." form and the legacy two-token "KEY VALUE" form.
func pairs(args []string) [][2]string {
	if len(args) == 2 && !strings.Contains(args[0], "=") {
		return [][2]string{{args[0], unquote(args[1])}}
	}
	var out [][2]string
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		out = append(out, [2]string{k, unquote(v)})
	}
	return out
}

// sortedKeys returns m's keys in order, for deterministic iteration.
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ensureEnv returns env with key=val appended only when key is not already set,
// so a caller-supplied default never overrides the image's own value.
func ensureEnv(env []string, key, val string) []string {
	for _, e := range env {
		if k, _, _ := strings.Cut(e, "="); k == key {
			return env
		}
	}
	return append(append([]string(nil), env...), key+"="+val)
}

// mergeEnv applies key/value pairs onto an environment, replacing an existing
// key in place and appending a new one.
func mergeEnv(env []string, kvs [][2]string) []string {
	idx := func(key string) int {
		for i, e := range env {
			if k, _, _ := strings.Cut(e, "="); k == key {
				return i
			}
		}
		return -1
	}
	for _, kv := range kvs {
		e := kv[0] + "=" + kv[1]
		if i := idx(kv[0]); i >= 0 {
			env[i] = e
		} else {
			env = append(env, e)
		}
	}
	return env
}

// abs resolves p against the working directory when it is relative.
func abs(workdir, p string) string {
	if path.IsAbs(p) {
		return path.Clean(p)
	}
	if workdir == "" {
		workdir = "/"
	}
	return path.Clean(path.Join(workdir, p))
}

// ownerIDs parses a "uid[:gid]" chown spec (numeric), defaulting gid to uid.
func ownerIDs(spec string) (uint32, uint32) {
	u, g, ok := strings.Cut(spec, ":")
	uid, _ := strconv.ParseUint(u, 10, 32)
	gid := uid
	if ok {
		if v, err := strconv.ParseUint(g, 10, 32); err == nil {
			gid = v
		}
	}
	return uint32(uid), uint32(gid)
}

func applyChown(l *hostfs.Layer, uid, gid uint32) { l.SetOwnerAll(uid, gid) }

// dstFSWrite creates name under dir with the given mode and writes data, using
// the backend's bulk WriteFile when it offers one. For COPY/ADD heredoc bodies.
func dstFSWrite(fsys vfs.FileSystem, dir vfs.Node, name string, mode uint32, data []byte) (vfs.Node, error) {
	if wfs, ok := fsys.(vfs.WriteFileSystem); ok {
		return wfs.WriteFile(dir, name, vfs.CreateSpec{Kind: vfs.Reg, Mode: mode}, data)
	}
	n, err := fsys.Create(dir, name, vfs.CreateSpec{Kind: vfs.Reg, Mode: mode})
	if err != nil {
		return nil, err
	}
	f, err := n.Open(os.O_WRONLY)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		f.Close()
		return nil, err
	}
	return n, f.Close()
}

// copyThroughVFS copies the source path src (resolved within srcNS) to the
// absolute destination dst (within dstNS). Both sides go through the vfs: the
// source is resolved one component at a time, confined to srcNS's root, so a
// symlink or ".." in a build context or a prior stage cannot read host files
// outside it; the destination's parent directories are created component by
// component, never through a symlink, so a planted link cannot carry the write
// out of the layer. It is the build's COPY/ADD on the same confined machinery
// the live guest uses.
func copyThroughVFS(srcNS *vfs.Namespace, src string, dstNS *vfs.Namespace, dst string, mode *uint32, ignore *ignoreMatcher) error {
	// followLast=false: a symlink named directly as the source is copied as a
	// symlink, as docker preserves it, not dereferenced.
	loc, err := srcNS.Resolve(src, false)
	if err != nil {
		return err
	}
	dir, err := mkdirAllVFS(dstNS, path.Dir(dst))
	if err != nil {
		return err
	}
	return copyNodeVFS(loc.FS, loc.Node, dir.FS, dir.Node, path.Base(dst), loc.Path, mode, ignore)
}

// mkdirAllVFS ensures the absolute directory dir exists within ns, creating each
// missing component through its FileSystem (never traversing a symlink), and
// returns its location. A component present as a non-directory is an error.
func mkdirAllVFS(ns *vfs.Namespace, dir string) (vfs.Loc, error) {
	cur, err := ns.Resolve("/", true)
	if err != nil {
		return vfs.Loc{}, err
	}
	for _, name := range strings.Split(strings.Trim(path.Clean(dir), "/"), "/") {
		if name == "" || name == "." {
			continue
		}
		child, err := cur.FS.Lookup(cur.Node, name)
		if err != nil {
			if child, err = cur.FS.Create(cur.Node, name, vfs.CreateSpec{Kind: vfs.Dir, Mode: 0o755}); err != nil {
				return vfs.Loc{}, err
			}
		}
		if child.Kind() != vfs.Dir {
			return vfs.Loc{}, fmt.Errorf("%s: not a directory", name)
		}
		cur = vfs.Loc{FS: cur.FS, Node: child}
	}
	return cur, nil
}

// copyNodeVFS copies the source node sn into ddir as name, recursively for a
// directory. Directories and symlinks are recreated; symlinks within a copied
// tree are preserved as links, never followed, so the walk stays confined.
// Special files (sockets, devices, fifos) are skipped, as the image unpacker is.
func copyNodeVFS(sfs vfs.FileSystem, sn vfs.Node, dfs vfs.FileSystem, ddir vfs.Node, name, srcPath string, mode *uint32, ignore *ignoreMatcher) error {
	if ignore.match(strings.TrimPrefix(path.Clean("/"+srcPath), "/")) {
		return nil
	}
	a, err := sn.Stat()
	if err != nil {
		return err
	}
	m := a.Mode // --chmod, when given, overrides the source mode on files and dirs
	if mode != nil {
		m = *mode
	}
	switch a.Kind {
	case vfs.Dir:
		dn, err := dfs.Create(ddir, name, vfs.CreateSpec{Kind: vfs.Dir, Mode: m})
		if err != nil {
			if dn, err = dfs.Lookup(ddir, name); err != nil {
				return err
			}
		}
		ents, err := sfs.ReadDir(sn)
		if err != nil {
			return err
		}
		for _, e := range ents {
			child, err := sfs.Lookup(sn, e.Name)
			if err != nil {
				return err
			}
			if err := copyNodeVFS(sfs, child, dfs, dn, e.Name, path.Join(srcPath, e.Name), mode, ignore); err != nil {
				return err
			}
		}
		return nil
	case vfs.Symlink:
		tgt, err := sn.Readlink()
		if err != nil {
			return err
		}
		_, err = dfs.Create(ddir, name, vfs.CreateSpec{Kind: vfs.Symlink, Target: tgt})
		return err
	case vfs.Reg:
		dn, err := dfs.Create(ddir, name, vfs.CreateSpec{Kind: vfs.Reg, Mode: m})
		if err != nil {
			if dn, err = dfs.Lookup(ddir, name); err != nil {
				return err
			}
		}
		return copyContentVFS(sn, dn, a.Size)
	default:
		return nil
	}
}

// copyContentVFS streams a regular file's bytes from sn to dn through the vfs
// File interface (ReaderAt/WriterAt), truncating the destination to the source
// size in case it already existed.
func copyContentVFS(sn, dn vfs.Node, size int64) error {
	in, err := sn.Open(os.O_RDONLY)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := dn.Open(os.O_WRONLY)
	if err != nil {
		return err
	}
	buf := make([]byte, 128*1024)
	var off int64
	for {
		n, rerr := in.ReadAt(buf, off)
		if n > 0 {
			if _, werr := out.WriteAt(buf[:n], off); werr != nil {
				out.Close()
				return werr
			}
			off += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			out.Close()
			return rerr
		}
	}
	if err := out.Truncate(off); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// modeBits are the permission and special bits a materialized file keeps: the
// 0777 permissions plus setuid, setgid and the sticky bit, so a directory like
// /tmp stays 1777 and a setuid binary keeps its bit — tools that run as a
// non-root user during a RUN (apt's _apt, say) need the real permissions.
const modeBits = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// copyTree recursively copies the directory src to dst (files, directories and
// symlinks), creating dst. Modes are set with Chmod, not through the create
// mode, so they survive the umask and keep the special bits. Special files are
// skipped, as the image unpacker skips them.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		fi, err := d.Info()
		if err != nil {
			return err
		}
		switch {
		case d.IsDir():
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			return os.Chmod(target, fi.Mode()&modeBits)
		case fi.Mode()&os.ModeSymlink != 0:
			tgt, err := os.Readlink(p)
			if err != nil {
				return err
			}
			os.Remove(target)
			return os.Symlink(tgt, target)
		case fi.Mode().IsRegular():
			if err := copyFileMode(p, target, fi.Mode().Perm()); err != nil {
				return err
			}
			return os.Chmod(target, fi.Mode()&modeBits)
		default:
			return nil // sockets, devices, fifos: skipped
		}
	})
}

func copyFileMode(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
