//go:build darwin

package sandbox

import (
	"encoding/binary"
	"os"
	"runtime"
	"unsafe"

	"github.com/samyfodil/laboon/core"
	"github.com/samyfodil/laboon/filesystems/hostfs"
)

// Shared code across stubs on Darwin (codereg.go): a page of memory is its
// VM object's id and offset, the same in every task; a stub asks the broker
// (brokerHot, brokerCool) and its service port answers the broker, a file
// named to it by inode (the stub knows Darwin's device numbers, the
// supervisor the guest's; a clash across devices only cools a page more).

const (
	brokerHot     = 0x4c430120 // stub -> broker: page; acked by brokerCodeAck
	brokerCool    = 0x4c430121
	brokerCodeAck = 0x4c430122
	brokerHotSet  = 0x4c430106 // broker -> a stub registering its service: the pages held

	svcFreeze   = 0x4c430114 // broker -> a stub's service: page
	svcCool     = 0x4c430115 // page
	svcCoolFile = 0x4c430116 // inode
	svcStop     = 0x4c430117 // cool every hot page, heat none until svcGo
	svcGo       = 0x4c430118
	svcAck      = 0x4c430119 // a stub's service: the reply to any of these
)

// brokerLink reaches stub pid's service port.
type brokerLink struct {
	b   *broker
	pid int
}

func (l brokerLink) tell(op codeOp, body []byte) bool {
	id := [...]int32{codeFreeze: svcFreeze, codeCool: svcCool, codeCoolFile: svcCoolFile, codeStop: svcStop, codeGo: svcGo}[op]
	return l.b.tell(l.pid, id, body)
}

// codeReq serves a stub's HOT or COOL of page x and acks it on reply.
func (b *broker) codeReq(id int32, pid int, x objPage, reply uint32) {
	if id == brokerHot {
		b.code.hot(pid, x)
	} else {
		b.code.cool(pid, x)
	}
	b.reply(reply, brokerCodeAck)
}

// tell sends stub pid's service request id with body and waits for its
// ack; false if the stub has ended. The request carries a send-once right
// for the ack: a stub ending with it, the kernel answers in its place.
func (b *broker) tell(pid int, id int32, body []byte) bool {
	b.mu.Lock()
	svc := b.services[pid]
	b.mu.Unlock()
	if svc == 0 {
		return false // not started yet, or ended: it holds no page
	}
	var kr int32
	task, right, reply := machTask, uint32(machPortRightReceive), uint32(0)
	rp := unsafe.Pointer(&reply)
	mpAllocate.call(unsafe.Pointer(&kr), unsafe.Pointer(&task), unsafe.Pointer(&right), unsafe.Pointer(&rp))
	if kr != 0 {
		return false
	}
	defer func() {
		delta := int32(-1)
		mpModRefs.call(unsafe.Pointer(&kr), unsafe.Pointer(&task), unsafe.Pointer(&reply), unsafe.Pointer(&right), unsafe.Pointer(&delta))
	}()
	msg := make([]byte, 24+len(body))
	h := (*machMsgHeader)(unsafe.Pointer(&msg[0]))
	*h = machMsgHeader{bits: machMsgTypeCopySend | machMsgTypeMakeSendOnce<<8, size: uint32(len(msg)), remote: svc, local: reply, id: id}
	copy(msg[24:], body)
	mp := unsafe.Pointer(&msg[0])
	opt, size, zero := int32(machSendMsg), h.size, uint32(0)
	mMsg.call(unsafe.Pointer(&kr), unsafe.Pointer(&mp), unsafe.Pointer(&opt), unsafe.Pointer(&size), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero))
	runtime.KeepAlive(msg)
	if kr != 0 {
		return false
	}
	var in [16]uint32
	ip := unsafe.Pointer(&in)
	opt, rcvSize := int32(machRcvMsg), uint32(unsafe.Sizeof(in))
	mMsg.call(unsafe.Pointer(&kr), unsafe.Pointer(&ip), unsafe.Pointer(&opt), unsafe.Pointer(&zero), unsafe.Pointer(&rcvSize), unsafe.Pointer(&reply), unsafe.Pointer(&zero), unsafe.Pointer(&zero))
	return kr == 0 && int32(in[5]) == svcAck
}

// reply sends an empty message id on the send-once right reply.
func (b *broker) reply(reply uint32, id int32) {
	if reply == 0 {
		return
	}
	m := machMsgHeader{bits: machMsgTypeMoveSendOnce, size: uint32(unsafe.Sizeof(machMsgHeader{})), remote: reply, id: id}
	mp := unsafe.Pointer(&m)
	opt, size, zero := int32(machSendMsg), m.size, uint32(0)
	var kr int32
	mMsg.call(unsafe.Pointer(&kr), unsafe.Pointer(&mp), unsafe.Pointer(&opt), unsafe.Pointer(&size), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero))
}

// replyHotSet answers a stub registering its service, on reply: the pages
// some stub holds, as of its registration.
func (b *broker) replyHotSet(reply uint32, set []byte) {
	if reply == 0 {
		return
	}
	type ool struct {
		h     machMsgHeader
		n     uint32
		addr  [2]uint32
		flags uint32 // deallocate, copy, pad, type (MACH_MSG_OOL_DESCRIPTOR)
		size  uint32
		count uint32
	}
	var addr uint64
	if len(set) > 0 {
		addr = uint64(uintptr(unsafe.Pointer(&set[0])))
	}
	m := ool{
		h:     machMsgHeader{bits: machMsgTypeMoveSendOnce | machMsgBitsComplex, size: uint32(unsafe.Sizeof(ool{})), remote: reply, id: brokerHotSet},
		n:     1,
		addr:  [2]uint32{uint32(addr), uint32(addr >> 32)},
		flags: 1<<8 | 1<<24, // copy, MACH_MSG_OOL_DESCRIPTOR
		size:  uint32(len(set)),
		count: uint32(len(set) / 16),
	}
	mp := unsafe.Pointer(&m)
	opt, size, zero := int32(machSendMsg), m.h.size, uint32(0)
	var kr int32
	mMsg.call(unsafe.Pointer(&kr), unsafe.Pointer(&mp), unsafe.Pointer(&opt), unsafe.Pointer(&size), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero), unsafe.Pointer(&zero))
	runtime.KeepAlive(set)
}

// codeStop readies p's stub for a host stop (codeStop above).
func (sr *sigRun) codeStop(p *sigProc) {
	if pid := sr.ospid(p); pid > 0 && sr.fs.run != nil {
		sr.fs.run.broker.code.stop(pid)
	}
}

// codeGo lets p's stub go on: what it owes cools before cont lets the host
// run it, and it heats again after.
func (sr *sigRun) codeGo(p *sigProc, cont func()) {
	pid := sr.ospid(p)
	if pid <= 0 || sr.fs.run == nil {
		cont()
		return
	}
	r := &sr.fs.run.broker.code
	going := r.going(pid)
	cont()
	if going {
		r.gone(pid)
	}
}

// codeFile records that g's stub maps the file fi shared and executable.
func (g *dguest) codeFile(fi os.FileInfo) {
	if g.dfs.run == nil || g.ps.ospid <= 0 {
		return
	}
	dev, ino := HostDevIno(fi)
	g.dfs.run.broker.code.mark(g.ps.ospid, [2]uint64{dev, ino})
}

// modified is a write to d's file: inotify hears of it, and the stubs that
// map the file shared and executable cool their hot pages of it.
func (g *dguest) modified(d *dfile) {
	g.notifyFd(d, inModify)
	if h := d.fsFile(); h != nil {
		g.fileModified(h)
	} else if d.f != nil {
		if fi, err := hostfs.FileStat(d.f); err == nil {
			g.infoModified(fi)
		}
	}
}

// fileModified cools the hot pages of f's file in the stubs that map it
// shared and executable.
func (g *dguest) fileModified(f core.File) {
	if info, err := f.Stat(); err == nil {
		g.infoModified(info)
	}
}

func (g *dguest) infoModified(fi os.FileInfo) {
	if g.dfs.run == nil {
		return
	}
	r := &g.dfs.run.broker.code
	if !r.marked() {
		return
	}
	if fi.Mode().IsRegular() {
		dev, ino := HostDevIno(fi)
		var body [8]byte
		binary.LittleEndian.PutUint64(body[:], ino)
		r.fileWritten([2]uint64{dev, ino}, body[:])
	}
}

// forkCode gives stub child the files its parent maps shared and
// executable, which it maps too.
func (fs *dfs) forkCode(parent, child int) {
	if fs.run != nil && parent > 0 {
		fs.run.broker.code.fork(parent, child)
	}
}

func (g *dguest) truncated(host func() (int, bool), truncate func() error) error {
	return truncate()
}
