//go:build darwin

package sandbox

import "runtime"

// An x86-64 guest single-steps with the trap flag, which Rosetta honours; an
// arm64 one cannot step from EL0 and steps in software (armStep).
const ptraceStepOK = runtime.GOARCH == "amd64"

func (m *memProc) ptraceInternalPC(uint64) bool { return false }
