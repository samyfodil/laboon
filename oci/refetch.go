package oci

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// fetchAttempts is how many times a layer download starts before a break in
// it fails the pull, as many as docker makes.
const fetchAttempts = 5

// refetchImage downloads a layer again when its download breaks off, as a
// registry's CDN may cut a long transfer.
type refetchImage struct {
	v1.Image
	ctx context.Context
}

func (i refetchImage) Layers() ([]v1.Layer, error) {
	ls, err := i.Image.Layers()
	if err != nil {
		return nil, err
	}
	out := make([]v1.Layer, len(ls))
	for n, l := range ls {
		out[n] = refetchLayer{l, i.ctx}
	}
	return out, nil
}

func (i refetchImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	l, err := i.Image.LayerByDigest(h)
	if err != nil {
		return nil, err
	}
	return refetchLayer{l, i.ctx}, nil
}

type refetchLayer struct {
	v1.Layer
	ctx context.Context
}

func (l refetchLayer) Compressed() (io.ReadCloser, error) {
	want, err := l.Digest()
	if err != nil {
		return nil, err
	}
	rc, err := l.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	return &refetchReader{l: l, rc: rc, want: want, sum: sha256.New(), tries: 1}, nil
}

// refetchReader reads a layer's blob, and when the transfer breaks, starts it
// again and skips what was already read. What it hands out is checked against
// the layer's digest, whichever transfer each part came from.
type refetchReader struct {
	l     refetchLayer
	rc    io.ReadCloser
	want  v1.Hash
	sum   hash.Hash
	off   int64
	tries int
}

func (r *refetchReader) Read(p []byte) (int, error) {
	for {
		n, err := r.rc.Read(p)
		r.sum.Write(p[:n])
		r.off += int64(n)
		if err == nil || n > 0 {
			return n, nil
		}
		if errors.Is(err, io.EOF) {
			if got := hex.EncodeToString(r.sum.Sum(nil)); r.want.Algorithm == "sha256" && got != r.want.Hex {
				return 0, fmt.Errorf("layer %s: read content with digest sha256:%s", r.want, got)
			}
			return 0, io.EOF
		}
		if r.tries >= fetchAttempts || r.l.ctx.Err() != nil {
			return 0, err
		}
		if rerr := r.restart(); rerr != nil {
			return 0, fmt.Errorf("%w; fetching again: %w", err, rerr)
		}
	}
}

// restart opens the blob again and reads up to where the last transfer broke.
func (r *refetchReader) restart() error {
	r.rc.Close()
	for r.tries < fetchAttempts && r.l.ctx.Err() == nil {
		r.tries++
		rc, err := r.l.Layer.Compressed()
		if err != nil {
			return err
		}
		if _, err := io.CopyN(io.Discard, rc, r.off); err == nil {
			r.rc = rc
			return nil
		}
		rc.Close()
	}
	if err := r.l.ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("every fetch broke off before byte %d", r.off)
}

func (r *refetchReader) Close() error { return r.rc.Close() }
