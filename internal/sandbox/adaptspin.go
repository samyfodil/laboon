package sandbox

import "sync/atomic"

// cputicks reads the CPU cycle counter (cputicks_amd64.s / cputicks_arm64.s).
func cputicks() uint64

// spinHint issues one PAUSE (x86) / YIELD (arm64): a spin-wait hint that yields
// the physical core to its SMT sibling and lowers spin power.
func spinHint()

// Adaptive spin. A waiter in the cross-process handshake spins on the shared
// state word before it parks on a futex; parking is event-driven but costs a
// wake latency (microseconds), so catching the answer during the spin is what
// keeps a hot workload fast. The question is how long to spin, and a fixed
// count is a hand-tuned hack: too short and a hot peer still parks, too long
// and an idle peer burns a core and oversubscribes the machine.
//
// Instead each channel learns its peer's own rhythm: the spin budget is driven
// by the latency at which the spin actually catches answers (mean + a few
// deviations of jitter), capped at this machine's measured park cost -- spinning
// longer than a park would cost can never pay. Back-to-back calls keep the
// budget small, so the waiter spins briefly and catches without parking; calls
// that are far apart decay the budget to zero, so the waiter parks at once (pure
// event-wait, no wasted spin). The only constants are measured on the running
// machine: the peer's rhythm and the park cost.

// parkCostCy is this machine's cost, in cputicks, to park on a futex and be
// woken: calibrateParkCost's figure at first, then following the wakes the
// waits see (parkSeen). The spin budget never exceeds it.
var parkCostCy atomic.Uint64

func parkCost() uint64 { return parkCostCy.Load() }

// parkSeen folds the latency of a wake that ended a park, stamped at by the
// waker, into the park cost: a median estimate, stepping a sixteenth toward
// each sample, so what parking costs on this machine as it runs now (a wake
// that finds its core asleep, say) caps the spins, and a rare long wake (a
// preempted waiter) barely moves it. The stub keeps its own (stub.zig).
func parkSeen(at uint64) {
	now, c := cputicks(), parkCostCy.Load()
	if at == 0 || now <= at || c == 0 {
		return
	}
	step := c>>4 | 1
	if now-at > c {
		c += step
	} else {
		c -= step
	}
	parkCostCy.Store(max(c, 1))
}

// spinner is a channel's per-peer estimator. The budget is driven by what the
// spin actually caught: meanCy is an EWMA of the latency at which requests are
// caught during the spin, madCy an EWMA of its deviation, and budgetCy is the
// spin budget set to mean + a few deviations (capped at the park cost). Driving
// the budget from caught latencies -- not from a predicted-vs-park gate -- is
// what keeps it robust: a hot slot's budget tracks its real arrival latency and
// never collapses, even if the measured park cost is off. A park only nudges
// the budget: up toward the cap when the request came soon after (worth spinning
// next time), down toward zero when it came far later (the slot has gone quiet,
// park at once -- pure event-wait, no wasted spin). A slot that falls quiet and
// then wakes recovers, because that first near park grows the budget again.
type spinner struct {
	budgetCy uint64 // current spin budget, ticks
	meanCy   uint64 // EWMA of caught-request latency
	madCy    uint64 // EWMA of its absolute deviation
	inited   bool
	woke     bool // the peer was asleep and this side woke it for this wait
}

// budget returns how many cputicks to spin before parking. A peer this side
// just woke answers a wake later than its rhythm, so the spin covers that
// wake too: otherwise this side parks in turn, the peer's answer has to wake
// it, and from then on every exchange pays two wakes.
func (s *spinner) budget() uint64 {
	b := parkCost() // cold: spin up to the competitive cap, then learn
	if s.inited {
		b = min(s.budgetCy, b)
	}
	if s.woke {
		b += parkCost()
	}
	return b
}

// wokePeer notes that this side woke the peer it is about to wait for.
func (s *spinner) wokePeer() { s.woke = true }

// hit records a request caught during the spin, k ticks after the wait began.
// A wait on a woken peer is not its rhythm and teaches nothing.
func (s *spinner) hit(k uint64) {
	if s.woke {
		s.woke = false
		return
	}
	if !s.inited {
		s.inited = true
		s.meanCy = k
		s.madCy = k >> 2
	} else {
		s.meanCy = s.meanCy - s.meanCy>>3 + k>>3
		d := k
		if d < s.meanCy {
			d = s.meanCy - k
		} else {
			d -= s.meanCy
		}
		s.madCy = s.madCy - s.madCy>>3 + d>>3
	}
	s.budgetCy = min(s.meanCy+4*s.madCy, parkCost()) // cover the jitter tail
}

// miss records a park: no request arrived within the budget, and g ticks (wake
// latency included) elapsed before one came. A near arrival grows the budget
// toward the cap; a far one decays it toward zero, reaching zero once it is a
// negligible fraction of a park -- then the slot parks straight away.
func (s *spinner) miss(g uint64) {
	if s.woke {
		s.woke = false
		return
	}
	s.inited = true
	c := parkCost()
	s.budgetCy = min(s.budgetCy, c)
	if g < 4*c {
		s.budgetCy += (c - s.budgetCy) >> 1
	} else {
		s.budgetCy -= s.budgetCy >> 2
		if s.budgetCy < c>>5 {
			s.budgetCy = 0
		}
	}
}
