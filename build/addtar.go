package build

import (
	"compress/bzip2"
	"compress/gzip"
	"io"
	"os"
	"strings"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/oci"
)

// archiveSuffixes are the local-archive extensions ADD auto-extracts, with the
// decompression each needs. xz and zstd are not handled (no stdlib reader).
var archiveSuffixes = map[string]string{
	".tar": "", ".tar.gz": "gz", ".tgz": "gz", ".tar.bz2": "bz2", ".tbz2": "bz2",
}

// isArchive reports whether name is a local archive ADD should extract, and how
// it is compressed.
func isArchive(name string) (comp string, ok bool) {
	lower := strings.ToLower(name)
	for suf, c := range archiveSuffixes {
		if strings.HasSuffix(lower, suf) {
			return c, true
		}
	}
	return "", false
}

// extractArchive unpacks the archive node n (compressed per comp) into the host
// directory dest, through oci.Unpack's confined (os.Root) extractor so a crafted
// entry cannot escape. dest is inside the step's layer directory.
func extractArchive(n core.Node, comp, dest string) error {
	a, err := n.Stat()
	if err != nil {
		return err
	}
	f, err := n.Open(os.O_RDONLY)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = io.NewSectionReader(f, 0, a.Size)
	switch comp {
	case "gz":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	case "bz2":
		r = bzip2.NewReader(r)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return oci.Unpack(r, dest, 16<<30)
}
