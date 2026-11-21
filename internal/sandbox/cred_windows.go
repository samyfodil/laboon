package sandbox

// recvCreds returns the SCM_CREDENTIALS control message to deliver with a
// received message when SO_PASSCRED is set: the creds its sender stamped on
// it, laid out within room bytes.
func (g *dguest) recvCreds(d *dfile, r *recvResult, room int) ([]byte, uint32) {
	s := d.sk
	if s == nil || s.family != lxAFUnix {
		return nil, 0
	}
	s.n.mu.Lock()
	v := s.opts[[2]int{lxSolSocket, lxSoPasscred}]
	s.n.mu.Unlock()
	if len(v) < 4 || le32(v) == 0 {
		return nil, 0
	}
	return g.credCmsg(r.cred, room)
}
