package sandbox

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// A run's temp files (channel, site lists, upper layer, memfds, ...) live in
// a directory of its own under TMPDIR, the supervisor process's, named
// lc-run-<pid>-<random> and removed when the run ends. The name cannot be
// guessed and the directory is always made new (mode 0700), so nothing
// another user put in TMPDIR is taken for it. The stubs' Seatbelt profile
// admits reads of their run's directory only. A supervisor killed outright
// cannot clean up after itself, so the first run in a later one removes what
// dead supervisors left behind, in the background: a TMPDIR with many
// entries takes a while to read.
var sweepOnce sync.Once

// runTmpPrefix starts the name of every run directory this process makes.
func runTmpPrefix() string {
	return "lc-run-" + strconv.Itoa(os.Getpid()) + "-"
}

// newRunTmp makes a run's temp directory, resolved on unix since the stubs'
// Seatbelt profile admits resolved paths only (TMPDIR is under the /var
// symlink).
func newRunTmp() (string, error) {
	sweepOnce.Do(func() { go sweepTmp() })
	d, err := os.MkdirTemp(os.TempDir(), runTmpPrefix())
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return d, nil
	}
	r, err := filepath.EvalSymlinks(d)
	if err != nil {
		os.RemoveAll(d)
		return "", err
	}
	return r, nil
}

// sweepDead removes the entries of dir named prefix<pid>[-...] whose
// process is gone.
func sweepDead(dir, prefix string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(strings.SplitN(rest, "-", 2)[0])
		if err != nil || pid == os.Getpid() || !pidGone(pid) {
			continue
		}
		os.RemoveAll(filepath.Join(dir, e.Name()))
	}
}
