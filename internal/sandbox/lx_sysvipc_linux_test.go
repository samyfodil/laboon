package sandbox

import (
	"encoding/binary"
	"os"
	"testing"
	"unsafe"
)

// Removing a set drops every process's SEM_UNDO adjustments for it, so a
// process that keeps creating, adjusting and removing sets holds no state for
// the removed ones.
func TestSemRmidClearsUndo(t *testing.T) {
	g := &dguest{mp: newMemProc(os.Getpid()), dfs: &dfs{}}
	defer dropIPC(g.dfs)
	ns := g.ipc()
	var op [6]byte
	binary.LittleEndian.PutUint16(op[2:], 1)
	binary.LittleEndian.PutUint16(op[4:], semUndo)
	addr := uint64(uintptr(unsafe.Pointer(&op[0])))
	for range 3 {
		id := ns.semget(g, 0, 1, ipcCreat|0o600)
		if id < 0 {
			t.Fatalf("semget: %d", id)
		}
		if r := ns.semop(g, int(id), addr, 1, 0); r != 0 {
			t.Fatalf("semop: %d", r)
		}
		if len(g.mp.semadj) != 1 || !ns.undo[g.mp] {
			t.Fatalf("after semop: semadj %v, undo %v", g.mp.semadj, ns.undo)
		}
		if r := ns.semctl(g, int(id), 0, ipcRmid, 0); r != 0 {
			t.Fatalf("IPC_RMID: %d", r)
		}
		if len(g.mp.semadj) != 0 || len(ns.undo) != 0 {
			t.Fatalf("after IPC_RMID: semadj %v, undo %v", g.mp.semadj, ns.undo)
		}
	}
}
