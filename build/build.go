package build

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
	"github.com/samyfodil/laboon/internal/namespace"
	"github.com/samyfodil/laboon/internal/rewrite"
	"github.com/samyfodil/laboon/internal/sandbox"
	"github.com/samyfodil/laboon/oci"
)

// Options configure a build.
type Options struct {
	Context   string            // build-context directory for COPY/ADD (default ".")
	Tag       string            // reference to give the image (default "laboon-build:latest")
	Platform  string            // "linux/amd64" or "linux/arm64"; empty is the host's
	Output    string            // path to write the image tarball (docker load format)
	Target    string            // build only up to this named stage; empty is the last
	Net       bool              // allow RUN steps to reach the network
	Store     bool              // also place the image in the oci cache, so laboon -image <tag> runs it
	BuildArgs map[string]string // --build-arg values, overriding ARG defaults
	CacheDir  string            // oci image cache; empty uses the default
	Cache     Cache             // build layer cache; nil disables step caching
	Plans     *rewrite.Cache    // RUN steps' rewrite plans (laboon.NewCache); nil keeps them in memory for this process
	Stdout    io.Writer         // RUN step output
	Stderr    io.Writer
}

// epoch is the fixed timestamp stamped on built layers and the config, so a
// rebuild of the same Dockerfile yields the same image.
var epoch = v1.Time{Time: time.Unix(0, 0).UTC()}

// Build runs a Dockerfile and writes the resulting image, returning its digest.
func Build(ctx context.Context, dockerfile io.Reader, opt Options) (v1.Hash, error) {
	var zero v1.Hash
	ins, err := Parse(dockerfile)
	if err != nil {
		return zero, err
	}
	global, stages, err := splitStages(ins)
	if err != nil {
		return zero, err
	}
	// Resolve the pre-FROM args and substitute them into each FROM line, so
	// FROM ${BASE} and FROM --platform=${P} work. The predefined args seed the
	// scope; a declared global arg (or --build-arg) overlays them.
	gargs := predefinedArgs(opt.Platform)
	for k, v := range argScope(global, opt.BuildArgs) {
		gargs[k] = v
	}
	for i := range stages {
		stages[i].from = expandVars(stages[i].from, gargs)
		if p, ok := stages[i].flags["platform"]; ok {
			stages[i].flags["platform"] = expandVars(p, gargs)
		}
	}
	if opt.Context == "" {
		opt.Context = "."
	}
	if opt.Tag == "" {
		opt.Tag = "laboon-build:latest"
	}
	ref, err := name.ParseReference(opt.Tag)
	if err != nil {
		return zero, fmt.Errorf("build: bad tag %q: %w", opt.Tag, err)
	}
	target := len(stages) - 1
	if opt.Target != "" {
		if target = stageIndex(stages, opt.Target); target < 0 {
			return zero, fmt.Errorf("build: no stage named %q", opt.Target)
		}
	}

	work, err := os.MkdirTemp("", "laboon-build-")
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(work)

	done := map[string]*builtStage{} // by stage name and by index, for COPY --from and FROM
	var layers []v1.Layer
	var cfg v1.Config
	for i := 0; i <= target; i++ {
		bs, err := buildStage(ctx, opt, work, i, stages[i], done, gargs)
		if err != nil {
			return zero, err
		}
		done[strconv.Itoa(i)] = bs
		if stages[i].name != "" {
			done[stages[i].name] = bs
		}
		if i == target {
			layers, cfg = bs.layers, *bs.cfg
		}
	}

	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return zero, err
	}
	if img, err = mutate.Config(img, cfg); err != nil {
		return zero, err
	}
	if img, err = mutate.CreatedAt(img, epoch); err != nil {
		return zero, err
	}
	// Stamp the platform so the image is a valid linux/<arch> image and the cache
	// keys it by the arch laboon runs (the host's, unless --platform overrode it).
	arch := runtime.GOARCH
	if _, a, ok := strings.Cut(opt.Platform, "/"); ok {
		arch = a
	}
	cfgFile, err := img.ConfigFile()
	if err != nil {
		return zero, err
	}
	cfgFile = cfgFile.DeepCopy()
	cfgFile.OS, cfgFile.Architecture = "linux", arch
	if img, err = mutate.ConfigFile(img, cfgFile); err != nil {
		return zero, err
	}
	if opt.Store {
		if _, err := oci.Store(img, opt.Tag, oci.Options{CacheDir: opt.CacheDir}); err != nil {
			return zero, fmt.Errorf("build: store %s in the image cache: %w", opt.Tag, err)
		}
	}
	if opt.Output != "" {
		if err := tarball.WriteToFile(opt.Output, ref, img); err != nil {
			return zero, err
		}
	}
	return img.Digest()
}

// stageDef is one FROM...stage of a (possibly multi-stage) Dockerfile.
type stageDef struct {
	name  string // the AS name, or "" if unnamed
	from  string // the FROM argument: an image ref, "scratch", or a prior stage
	flags map[string]string
	instr []Instruction // the stage's instructions after its FROM
}

// splitStages groups a Dockerfile's instructions by their FROM lines, returning
// any pre-FROM ARG instructions (the global build args, usable in FROM) first.
// Only ARG may precede the first FROM, as docker requires.
func splitStages(ins []Instruction) (global []Instruction, stages []stageDef, err error) {
	for _, in := range ins {
		if len(stages) == 0 && in.Cmd != "FROM" {
			if in.Cmd == "ARG" {
				global = append(global, in)
				continue
			}
			return nil, nil, fmt.Errorf("build: line %d: only ARG may come before the first FROM", in.Line)
		}
		if in.Cmd == "FROM" {
			if len(in.Args) == 0 {
				return nil, nil, fmt.Errorf("build: line %d: FROM needs an image", in.Line)
			}
			name := ""
			if len(in.Args) >= 3 && strings.EqualFold(in.Args[1], "AS") {
				name = in.Args[2]
			}
			stages = append(stages, stageDef{name: name, from: in.Args[0], flags: in.Flags})
			continue
		}
		stages[len(stages)-1].instr = append(stages[len(stages)-1].instr, in)
	}
	if len(stages) == 0 {
		return nil, nil, fmt.Errorf("build: the first instruction must be FROM")
	}
	return global, stages, nil
}

func stageIndex(stages []stageDef, ref string) int {
	for i, s := range stages {
		if s.name == ref {
			return i
		}
	}
	if n, err := strconv.Atoi(ref); err == nil && n >= 0 && n < len(stages) {
		return n
	}
	return -1
}

// builtStage is a finished stage: its materialized root (for COPY --from and a
// later FROM), its image layers and its config.
type builtStage struct {
	root   string
	layers []v1.Layer
	cfg    *v1.Config
	key    string // final cache chain key, seeds a later FROM of this stage
}

// buildStage resolves a stage's base (a prior stage, scratch, or a pulled
// image), materializes it into a fresh root and runs the stage's instructions.
func buildStage(ctx context.Context, opt Options, work string, idx int, st stageDef, done map[string]*builtStage, gargs map[string]string) (*builtStage, error) {
	root := filepath.Join(work, fmt.Sprintf("stage-%d-root", idx))
	arch := ""
	if _, a, ok := strings.Cut(opt.Platform, "/"); ok {
		arch = a
	}
	var cfg v1.Config
	var layers []v1.Layer
	var baseID string // seeds the cache chain key; identifies this stage's base

	switch {
	case done[st.from] != nil: // FROM a prior stage
		src := done[st.from]
		if err := copyTree(src.root, root); err != nil {
			return nil, fmt.Errorf("build: stage %d base %q: %w", idx, st.from, err)
		}
		cfg = *src.cfg
		base, err := layerFromDir(src.root, filepath.Join(work, fmt.Sprintf("stage-%d-base.tar", idx)))
		if err != nil {
			return nil, err
		}
		layers = []v1.Layer{base}
		baseID = src.key
	case st.from == "scratch":
		if err := os.MkdirAll(root, 0o755); err != nil {
			return nil, err
		}
		baseID = "scratch/" + arch
	default: // a pulled image
		img, err := oci.Pull(ctx, st.from, oci.Options{CacheDir: opt.CacheDir, Arch: arch})
		if err != nil {
			return nil, fmt.Errorf("build: FROM %s: %w", st.from, err)
		}
		if err := copyTree(img.Root, root); err != nil {
			return nil, fmt.Errorf("build: stage %d base: %w", idx, err)
		}
		cfg = baseConfig(img.Config)
		base, err := layerFromDir(img.Root, filepath.Join(work, fmt.Sprintf("stage-%d-base.tar", idx)))
		if err != nil {
			return nil, err
		}
		layers = []v1.Layer{base}
		baseID = img.Digest
	}

	ignore, err := loadDockerignore(opt.Context)
	if err != nil {
		return nil, err
	}
	b := &builder{opt: opt, work: work, root: root, cfg: &cfg, sidx: idx, stages: done,
		args: map[string]string{}, gargs: gargs, ignore: ignore}
	key := baseID
	for _, in := range st.instr {
		in = b.expand(in)
		content, err := b.contentHash(in)
		if err != nil {
			return nil, fmt.Errorf("build: line %d: %s: %w", in.Line, in.Cmd, err)
		}
		key = stepKey(key, in, content)
		// Reuse a cached layer for a producing step whose chain key is unchanged.
		if opt.Cache != nil && producesLayer(in.Cmd) {
			if layer, ok := opt.Cache.Get(key); ok {
				if err := b.applyLayer(layer); err != nil {
					return nil, fmt.Errorf("build: line %d: %s: cache apply: %w", in.Line, in.Cmd, err)
				}
				layers = append(layers, layer)
				continue
			}
		}
		layer, err := b.run(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("build: line %d: %s: %w", in.Line, in.Cmd, err)
		}
		if layer != nil {
			layers = append(layers, layer)
			if opt.Cache != nil {
				if err := opt.Cache.Put(key, layer); err != nil {
					return nil, fmt.Errorf("build: line %d: %s: cache store: %w", in.Line, in.Cmd, err)
				}
			}
		}
	}
	return &builtStage{root: root, layers: layers, cfg: &cfg, key: key}, nil
}

// producesLayer reports whether an instruction yields a filesystem layer (and so
// is worth caching); the metadata instructions do not.
func producesLayer(cmd string) bool { return cmd == "RUN" || cmd == "COPY" || cmd == "ADD" }

// isDir reports whether the guest-absolute path gp already exists as a directory
// in the stage's working root, so COPY knows to place a file inside it.
func (b *builder) isDir(gp string) bool {
	fi, err := os.Stat(filepath.Join(b.root, filepath.FromSlash(gp)))
	return err == nil && fi.IsDir()
}

// srcRoot is the directory a COPY/ADD reads from: a prior stage's root with
// --from, otherwise the build context.
func (b *builder) srcRoot(in Instruction) (string, error) {
	if from := in.Flags["from"]; from != "" {
		st := b.stages[from]
		if st == nil {
			return "", fmt.Errorf("--from=%s: no such stage", from)
		}
		return st.root, nil
	}
	return b.opt.Context, nil
}

// contentHash is the cache-key contribution of a COPY/ADD's sources (their file
// content), so editing a copied file misses the cache. Other instructions have
// none — their text alone keys them.
func (b *builder) contentHash(in Instruction) (string, error) {
	// RUN takes its ARG values from the environment, which ${VAR} substitution
	// does not capture, so fold the in-scope args into its key — a changed
	// --build-arg then invalidates the cached step.
	if in.Cmd == "RUN" {
		var sb strings.Builder
		for _, k := range sortedKeys(b.args) {
			sb.WriteString(k + "=" + b.args[k] + "\x00")
		}
		return sb.String(), nil
	}
	if in.Cmd != "COPY" && in.Cmd != "ADD" || len(in.Args) < 2 {
		return "", nil
	}
	root, err := b.srcRoot(in)
	if err != nil {
		return "", err
	}
	var roots []string
	for _, src := range in.Args[:len(in.Args)-1] {
		if isURL(src) {
			continue // a URL has no local tree; the URL in the instruction keys it
		}
		roots = append(roots, filepath.Join(root, filepath.FromSlash(src)))
	}
	return hashTrees(roots)
}

// applyLayer folds a cached layer into the working root, as running the step
// would have, so a later step sees its files.
func (b *builder) applyLayer(layer v1.Layer) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return err
	}
	defer rc.Close()
	b.step++
	dir := filepath.Join(b.work, fmt.Sprintf("stage-%d-cache-%d", b.sidx, b.step))
	l, err := oci.ReadTar(rc, dir)
	if err != nil {
		return err
	}
	return l.ApplyTo(b.root)
}

type builder struct {
	opt    Options
	work   string
	root   string
	cfg    *v1.Config
	sidx   int // stage index, for unique scratch filenames
	step   int
	stages map[string]*builtStage // prior stages, for COPY --from
	args   map[string]string      // ARG values in scope: for ${VAR} and RUN's env
	gargs  map[string]string      // resolved pre-FROM args, for a re-declared ARG to inherit
	ignore *ignoreMatcher         // the context's .dockerignore, for COPY/ADD from the context
}

// scope is the variables available for ${VAR} substitution: the ARG values
// overlaid by ENV (ENV wins for a shared name), matching docker.
func (b *builder) scope() map[string]string {
	m := make(map[string]string, len(b.args)+len(b.cfg.Env))
	for k, v := range b.args {
		m[k] = v
	}
	for _, e := range b.cfg.Env {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}

// expand substitutes ${VAR} in an instruction's arguments and flags for the
// instructions docker substitutes; others pass through unchanged.
func (b *builder) expand(in Instruction) Instruction {
	if !substituteIn[in.Cmd] {
		return in
	}
	sc := b.scope()
	out := in
	out.Args = make([]string, len(in.Args))
	for i, a := range in.Args {
		// Expand ${VAR}, then strip the surrounding quotes docker allows around an
		// argument (a COPY/ADD path, say). ENV/LABEL unquote the value in pairs.
		out.Args[i] = unquote(expandVars(a, sc))
	}
	if len(in.Flags) > 0 {
		out.Flags = make(map[string]string, len(in.Flags))
		for k, v := range in.Flags {
			out.Flags[k] = expandVars(v, sc)
		}
	}
	return out
}

// setArg records an ARG's value in scope: a --build-arg value wins, else the
// instruction's default, else an inherited pre-FROM value, else empty.
func (b *builder) setArg(tok string) {
	name, def, hasDef := parseArg(tok)
	switch {
	case b.opt.BuildArgs[name] != "":
		b.args[name] = b.opt.BuildArgs[name]
	case hasDef:
		b.args[name] = def
	default:
		b.args[name] = b.gargs[name] // "" if not a pre-FROM arg
	}
}

// run interprets one instruction, returning a new image layer when it changes
// the filesystem.
func (b *builder) run(ctx context.Context, in Instruction) (v1.Layer, error) {
	switch in.Cmd {
	case "RUN":
		return b.exec(ctx, in)
	case "COPY", "ADD":
		return b.copy(in)
	case "ENV":
		b.cfg.Env = mergeEnv(b.cfg.Env, pairs(in.Args))
		return nil, nil
	case "WORKDIR":
		if len(in.Args) == 1 {
			b.cfg.WorkingDir = abs(b.cfg.WorkingDir, in.Args[0])
			rel := filepath.FromSlash(b.cfg.WorkingDir)
			if _, err := os.Stat(filepath.Join(b.root, rel)); err == nil {
				return nil, nil // already present (e.g. an existing dir), no new layer
			}
			// Create the directory in a fresh upper and capture it as a layer, so
			// WORKDIR persists into the image (and the guest can chdir into it) as
			// docker does — not just a config field over a missing directory.
			upper := b.stepDir()
			if err := os.MkdirAll(filepath.Join(upper, rel), 0o755); err != nil {
				return nil, err
			}
			return b.capture(upper)
		}
		return nil, nil
	case "USER":
		if len(in.Args) == 1 {
			b.cfg.User = in.Args[0]
		}
		return nil, nil
	case "CMD":
		b.cfg.Cmd = shellOrExec(in)
		return nil, nil
	case "ENTRYPOINT":
		b.cfg.Entrypoint = shellOrExec(in)
		return nil, nil
	case "LABEL":
		if b.cfg.Labels == nil {
			b.cfg.Labels = map[string]string{}
		}
		for _, kv := range pairs(in.Args) {
			b.cfg.Labels[kv[0]] = kv[1]
		}
		return nil, nil
	case "EXPOSE":
		if b.cfg.ExposedPorts == nil {
			b.cfg.ExposedPorts = map[string]struct{}{}
		}
		for _, p := range in.Args {
			b.cfg.ExposedPorts[p] = struct{}{}
		}
		return nil, nil
	case "ARG":
		if len(in.Args) == 1 {
			b.setArg(in.Args[0])
		}
		return nil, nil
	case "ONBUILD":
		if len(in.Args) > 0 {
			b.cfg.OnBuild = append(b.cfg.OnBuild, strings.Join(in.Args, " "))
		}
		return nil, nil
	case "VOLUME", "MAINTAINER", "STOPSIGNAL", "HEALTHCHECK", "SHELL":
		return nil, nil // recognized but not yet acted on
	default:
		return nil, fmt.Errorf("unsupported instruction")
	}
}

// exec runs a RUN step in the working root and captures its changes as a layer.
func (b *builder) exec(ctx context.Context, in Instruction) (v1.Layer, error) {
	argv := in.Args
	if !in.Exec {
		argv = []string{"/bin/sh", "-c", in.Args[0]}
	}
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty RUN")
	}
	upper := b.stepDir()
	// RUN sees the ARG values as environment (docker does), with ENV winning a
	// shared name, plus HOME=/root (where docker's RUN points it) unless set, so
	// tools that need a home — go's build cache, npm, pip — work. Both are RUN-time
	// only, not written into the image's Env.
	env := b.cfg.Env
	for _, k := range sortedKeys(b.args) {
		env = ensureEnv(env, k, b.args[k])
	}
	code, err := sandbox.Run(ctx, argv[0], sandbox.Config{
		Args:   argv,
		Env:    ensureEnv(env, "HOME", "/root"),
		RootFS: sandbox.HostRoot(b.root),
		Upper:  upper,
		Dir:    b.cfg.WorkingDir,
		Net:    b.opt.Net,
		Stdout: b.opt.Stdout,
		Stderr: b.opt.Stderr,
		Cache:  b.opt.Plans,
	})
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("command exited %d", code)
	}
	return b.capture(upper)
}

// copy brings build-context files into the image as a layer.
func (b *builder) copy(in Instruction) (v1.Layer, error) {
	// A heredoc supplies its own content, so it needs only a destination.
	need := 2
	if in.Heredoc != "" {
		need = 1
	}
	if len(in.Args) < need {
		return nil, fmt.Errorf("needs a source and a destination")
	}
	dst := in.Args[len(in.Args)-1]
	srcs := in.Args[:len(in.Args)-1]
	srcRoot, err := b.srcRoot(in)
	if err != nil {
		return nil, err
	}
	upper := b.stepDir()
	// Resolve sources confined to their root and write the layer confined to the
	// step directory, both through the vfs, so COPY/ADD cannot escape the build
	// context or a prior stage via a symlink or "..".
	srcNS := namespace.NewNamespace(hostfs.NewDirFS(srcRoot))
	dstNS := namespace.NewNamespace(hostfs.NewDirFS(upper))
	// .dockerignore applies to the build context, not a --from stage.
	var ignore *ignoreMatcher
	if in.Flags["from"] == "" {
		ignore = b.ignore
	}
	// --chmod sets the copied files' and directories' mode; otherwise the source's.
	var chmod *uint32
	if c := in.Flags["chmod"]; c != "" {
		if n, perr := strconv.ParseUint(c, 8, 32); perr == nil {
			m := uint32(n)
			chmod = &m
		} else {
			return nil, fmt.Errorf("bad --chmod %q", c)
		}
	}
	// A COPY/ADD heredoc writes its body to the destination file.
	if in.Heredoc != "" {
		to := abs(b.cfg.WorkingDir, dst)
		dir, err := mkdirAllVFS(dstNS, path.Dir(to))
		if err != nil {
			return nil, err
		}
		mode := uint32(0o644)
		if chmod != nil {
			mode = *chmod
		}
		if _, err := dstFSWrite(dir.FS, dir.Node, path.Base(to), mode, []byte(in.Heredoc)); err != nil {
			return nil, err
		}
	}
	// The destination is a directory when it ends in "/", there are several
	// sources, or it already exists as a directory — then a file source lands
	// inside it under its base name (docker's rule), not as the directory's
	// replacement.
	destDir := strings.HasSuffix(dst, "/") || len(srcs) > 1 || b.isDir(abs(b.cfg.WorkingDir, dst))
	for _, src := range srcs {
		// ADD from an http(s) URL downloads to the destination (no extraction,
		// as docker). Network access is gated by --net, like RUN's.
		if in.Cmd == "ADD" && isURL(src) {
			if !b.opt.Net {
				return nil, fmt.Errorf("ADD %s: fetching a URL needs --net", src)
			}
			name := dst
			if destDir {
				name = path.Join(dst, path.Base(src))
			}
			dest := filepath.Join(upper, filepath.FromSlash(abs(b.cfg.WorkingDir, name)))
			if err := fetchURL(src, dest); err != nil {
				return nil, fmt.Errorf("ADD %s: %w", src, err)
			}
			continue
		}
		// ADD unpacks a local archive from the context into the destination
		// directory, as docker does; COPY and ADD --from never extract.
		if in.Cmd == "ADD" && in.Flags["from"] == "" {
			if comp, ok := isArchive(src); ok {
				loc, rerr := srcNS.Resolve(src, true)
				if rerr != nil {
					return nil, rerr
				}
				if err := extractArchive(loc.Node, comp, filepath.Join(upper, filepath.FromSlash(abs(b.cfg.WorkingDir, dst)))); err != nil {
					return nil, err
				}
				continue
			}
		}
		// A single directory source copies its contents into dst (dst becomes that
		// directory); a file, or any source when there are several, lands under its
		// base name inside dst.
		srcIsDir := false
		if loc, e := srcNS.Resolve(src, false); e == nil && loc.Node.Kind() == core.Dir {
			srcIsDir = true
		}
		to := dst
		if destDir && (len(srcs) > 1 || !srcIsDir) {
			to = path.Join(dst, path.Base(src))
		}
		if err := copyThroughVFS(srcNS, src, dstNS, abs(b.cfg.WorkingDir, to), chmod, ignore); err != nil {
			return nil, err
		}
	}
	// --chown=uid:gid sets the layer's owner; otherwise root.
	layer, err := hostfs.LayerFromDir(upper)
	if err != nil {
		return nil, err
	}
	if own := in.Flags["chown"]; own != "" {
		uid, gid := ownerIDs(own)
		applyChown(layer, uid, gid)
	}
	// The permission bits of --chmod are set on the host files as they are
	// copied; its special bits (setuid/setgid/sticky) a host file cannot hold,
	// so record them as layer overrides that carry into the image.
	if chmod != nil && *chmod&0o7000 != 0 {
		layer.SetModeAll(*chmod)
	}
	if err := layer.ApplyTo(b.root); err != nil {
		return nil, err
	}
	return b.tarLayer(layer)
}

// capture turns a run's kept upper directory into an image layer and folds it
// into the working root for the next step.
func (b *builder) capture(upper string) (v1.Layer, error) {
	layer, err := hostfs.LayerFromDir(upper)
	if err != nil {
		return nil, err
	}
	if err := layer.ApplyTo(b.root); err != nil {
		return nil, err
	}
	return b.tarLayer(layer)
}

func (b *builder) tarLayer(layer *hostfs.Layer) (v1.Layer, error) {
	b.step++
	tp := filepath.Join(b.work, fmt.Sprintf("stage-%d-layer-%d.tar", b.sidx, b.step))
	f, err := os.Create(tp)
	if err != nil {
		return nil, err
	}
	if err := oci.WriteTar(layer.ChangeSet(), f); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return tarball.LayerFromFile(tp)
}

func (b *builder) stepDir() string {
	b.step++
	d := filepath.Join(b.work, fmt.Sprintf("stage-%d-step-%d", b.sidx, b.step))
	os.MkdirAll(d, 0o755)
	return d
}

func layerFromDir(dir, tarPath string) (v1.Layer, error) {
	layer, err := hostfs.LayerFromDir(dir)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(tarPath)
	if err != nil {
		return nil, err
	}
	if err := oci.WriteTar(layer.ChangeSet(), f); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return tarball.LayerFromFile(tarPath)
}
