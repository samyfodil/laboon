package sandbox

// The shared table is keyed by the arm64 numbers themselves, so an arm64 guest
// needs no translation.
func toGeneric(nr uint64, a [6]uint64) (uint64, [6]uint64, bool) { return nr, a, true }

func fromGeneric(nr uint64, a [6]uint64, r int64) int64 { return r }
