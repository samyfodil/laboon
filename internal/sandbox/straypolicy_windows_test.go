package sandbox

import "testing"

// TestStrayPolicy: stray syscall encodings a rewrite leaves are kept unless
// StrictRewrite refuses the image.
func TestStrayPolicy(t *testing.T) {
	stray := []uint64{0x401000}
	if err := (&wguest{}).strayPolicy(stray); err != nil {
		t.Fatalf("lenient: %v", err)
	}
	strict := &wguest{cfg: Config{StrictRewrite: true}}
	if err := strict.strayPolicy(nil); err != nil {
		t.Fatalf("strict, none left: %v", err)
	}
	if err := strict.strayPolicy(stray); err == nil {
		t.Fatal("strict: an image with a stray encoding was not refused")
	}
}
