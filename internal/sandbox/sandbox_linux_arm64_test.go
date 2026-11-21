package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// protBTI matches a traced mmap or mprotect (arm64 222, 226) whose prot is
// PROT_READ|PROT_EXEC|PROT_BTI; the trace prints all six argument registers.
var protBTI = regexp.MustCompile(`\] 22[26]\(0x[0-9a-f]+, 0x[0-9a-f]+, 0x15, `)

// glibc maps each BTI library's code a second time with PROT_BTI added. The
// code is already rewritten and unchanged, so it must not be rewritten again
// (each rewrite also takes a new trampoline chunk).
func TestBTIRemapKeepsRewrittenCode(t *testing.T) {
	rewrites := map[bool]int{}
	for _, bti := range []bool{false, true} {
		var flags []string
		if bti {
			flags = []string{"-mbranch-protection=standard", "-Wl,-z,force-bti"}
		}
		root := t.TempDir()
		lib, exe := filepath.Join(root, "lib", "libbti.so"), filepath.Join(root, "btimain")
		if err := os.Mkdir(filepath.Dir(lib), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, c := range [][]string{
			append([]string{"-O2", "-fPIC", "-shared", "-o", lib, "../../testdata/btilib.c"}, flags...),
			append([]string{"-O2", "-o", exe, "../../testdata/btimain.c", "-L" + filepath.Dir(lib), "-lbti", "-Wl,-rpath,/lib"}, flags...),
		} {
			if b, err := exec.Command("gcc", c...).CombinedOutput(); err != nil {
				t.Fatalf("gcc: %v\n%s", err, b)
			}
		}
		withLibs(t, root, exe)
		var o, trace bytes.Buffer
		code, err := Run(context.Background(), "/btimain", Config{Args: []string{"btimain"}, Stdout: &o, Stderr: &o, Trace: &trace, RootFS: HostRoot(root)})
		if err != nil || code != 0 || o.String() != "bti_add=5\n" {
			t.Fatalf("bti=%v: code=%d err=%v out=%q", bti, code, err, o.String())
		}
		if bti && !protBTI.MatchString(trace.String()) {
			t.Fatalf("no PROT_BTI mapping in the trace")
		}
		rewrites[bti] = strings.Count(trace.String(), "rewriting code at")
	}
	if rewrites[true] != rewrites[false] {
		t.Fatalf("code rewrites: %d with BTI, %d without", rewrites[true], rewrites[false])
	}
}
