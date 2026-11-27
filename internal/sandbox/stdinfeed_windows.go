package sandbox

import "os"

// pipeHeld is not asked on Windows, where the feed streams from the start.
func pipeHeld(*os.File) (int, error) { return 0, nil }
