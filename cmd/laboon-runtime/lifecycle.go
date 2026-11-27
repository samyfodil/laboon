package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/samyfodil/laboon"
)

// cmdPause and cmdResume freeze and thaw the container by SIGSTOP/SIGCONT on the
// guest's host process group.
func cmdPause(root string, args []string) int {
	s, err := loadState(root, lastArg(args))
	if err != nil {
		die(err)
	}
	if s.GuestPid <= 0 {
		die(fmt.Errorf("container %q has no running process to pause", s.ID))
	}
	if err := syscall.Kill(-s.GuestPid, syscall.SIGSTOP); err != nil {
		die(err)
	}
	s.Status = "paused"
	s.save(root)
	return 0
}

func cmdResume(root string, args []string) int {
	s, err := loadState(root, lastArg(args))
	if err != nil {
		die(err)
	}
	if s.GuestPid <= 0 {
		die(fmt.Errorf("container %q has no process to resume", s.ID))
	}
	if err := syscall.Kill(-s.GuestPid, syscall.SIGCONT); err != nil {
		die(err)
	}
	s.Status = "running"
	s.save(root)
	return 0
}

// state is what laboon-runtime persists per container so the create/start/kill/
// delete calls (made as separate processes) share one view.
type state struct {
	OCIVersion string `json:"ociVersion"`
	ID         string `json:"id"`
	Pid        int    `json:"pid"`      // the detached monitor's host pid
	GuestPid   int    `json:"guestPid"` // the guest's host leader pid, for pause/unpause
	Status     string `json:"status"`
	Bundle     string `json:"bundle"`
	Rootfs     string `json:"rootfs"`
	ExitCode   int    `json:"exitCode"`
}

func stateDir(root, id string) string { return filepath.Join(root, id) }

func loadState(root, id string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(stateDir(root, id), "state.json"))
	if err != nil {
		return nil, fmt.Errorf("container %q does not exist", id)
	}
	var s state
	return &s, json.Unmarshal(b, &s)
}

func (s *state) save(root string) error {
	b, _ := json.Marshal(s)
	return os.WriteFile(filepath.Join(stateDir(root, s.ID), "state.json"), b, 0o600)
}

func alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }

// cmdCreate prepares a container and leaves it held at a start barrier: a
// detached monitor process is forked that waits on a fifo until start, then runs
// the workload. The engine then calls start, state, kill and delete.
func cmdCreate(root string, args []string) int {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	bundle := fs.String("bundle", ".", "path to the OCI bundle")
	pidFile := fs.String("pid-file", "", "write the monitor pid here")
	consoleSocket := fs.String("console-socket", "", "socket to pass the terminal master to")
	// Flags the containerd shim and runc CLI also pass; accepted and ignored so
	// the runtime is a drop-in.
	fs.Bool("no-pivot", false, "")
	fs.Bool("no-new-keyring", false, "")
	fs.Int("preserve-fds", 0, "")
	fs.Parse(args)
	id := fs.Arg(0)
	if id == "" {
		die(fmt.Errorf("create: no container id"))
	}
	if _, err := os.Stat(stateDir(root, id)); err == nil {
		die(fmt.Errorf("container %q already exists", id))
	}
	abs, err := filepath.Abs(*bundle)
	if err != nil {
		die(err)
	}
	_, rootfs, err := loadSpec(abs)
	if err != nil {
		die(err)
	}
	dir := stateDir(root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		die(err)
	}
	fifo := filepath.Join(dir, "exec.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		die(err)
	}
	s := &state{OCIVersion: "1.0.2", ID: id, Status: "creating", Bundle: abs, Rootfs: rootfs}
	s.save(root)

	// The container's stdio: a pty slave for a terminal container (the engine
	// gets the master over the console socket), else the stdio the engine gave us
	// (its fifos). The detached monitor inherits it and survives via its session.
	stdin, stdout, stderr := os.Stdin, os.Stdout, os.Stderr
	if *consoleSocket != "" {
		slave, err := setupConsole(*consoleSocket)
		if err != nil {
			os.RemoveAll(dir)
			die(err)
		}
		stdin, stdout, stderr = slave, slave, slave
	}
	self, _ := os.Executable()
	cmd := exec.Command(self, "__monitor", root, id)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		die(err)
	}
	s.Pid, s.Status = cmd.Process.Pid, "created"
	s.save(root)
	if *pidFile != "" {
		os.WriteFile(*pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644)
	}
	cmd.Process.Release()
	return 0
}

// cmdMonitor is the detached container monitor: it waits on the start fifo, runs
// the workload through laboon, forwards signals to the guest, and records the
// exit. It is re-exec'd by create and is not a user-facing command.
func cmdMonitor(args []string) int {
	if len(args) < 2 {
		return 1
	}
	root, id := args[0], args[1]
	s, err := loadState(root, id)
	if err != nil {
		return 1
	}
	spec, rootfs, err := loadSpec(s.Bundle)
	if err != nil {
		return 1
	}
	// Block until start opens the fifo for writing.
	f, err := os.OpenFile(filepath.Join(stateDir(root, id), "exec.fifo"), os.O_RDONLY, 0)
	if err != nil {
		return 1
	}
	var one [1]byte
	f.Read(one[:])
	f.Close()

	prog, opts := specOptions(spec, rootfs, os.Stdin, os.Stdout, os.Stderr)
	proc, err := laboon.Start(context.Background(), prog, opts...)
	if err != nil {
		s.Status = "stopped"
		s.ExitCode = 1
		s.save(root)
		return 1
	}
	// Record the guest's host leader pid (its own process group) once the stub is
	// up, so pause/unpause can SIGSTOP/SIGCONT it.
	for i := 0; i < 500 && proc.Pid() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	s.GuestPid = proc.Pid()
	s.Status = "running"
	s.save(root)

	// Forward catchable signals (kill sends them to us) to the guest's init.
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range sigc {
			proc.Signal(sig)
		}
	}()

	code, _ := proc.Wait()
	plans.Sync()
	s.Status, s.ExitCode = "stopped", code
	s.save(root)
	return code // the shim reaps the monitor; its exit status is the container's
}

func cmdStart(root string, args []string) int {
	id := lastArg(args)
	s, err := loadState(root, id)
	if err != nil {
		die(err)
	}
	if s.Status != "created" {
		die(fmt.Errorf("container %q is %s, not created", id, s.Status))
	}
	// Opening the fifo for writing releases the monitor blocked on the read.
	f, err := os.OpenFile(filepath.Join(stateDir(root, id), "exec.fifo"), os.O_WRONLY, 0)
	if err != nil {
		die(err)
	}
	f.Write([]byte{0})
	f.Close()
	return 0
}

func cmdState(root string, args []string) int {
	id := lastArg(args)
	s, err := loadState(root, id)
	if err != nil {
		die(err)
	}
	status := s.Status
	if status == "running" && !alive(s.Pid) {
		status = "stopped"
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"ociVersion": s.OCIVersion,
		"id":         s.ID,
		"status":     status,
		"pid":        s.Pid,
		"bundle":     s.Bundle,
	})
	return 0
}

func cmdKill(root string, args []string) int {
	var pos []string // runc kill is `<id> [signal]`, after any flags (--all)
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
		}
	}
	id := ""
	if len(pos) > 0 {
		id = pos[0]
	}
	sig := syscall.SIGTERM
	if len(pos) > 1 {
		if p := parseSignal(pos[1]); p != 0 {
			sig = p
		}
	}
	s, err := loadState(root, id)
	if err != nil {
		die(err)
	}
	if !alive(s.Pid) {
		die(fmt.Errorf("container %q is not running", id))
	}
	if err := syscall.Kill(s.Pid, sig); err != nil {
		die(err)
	}
	return 0
}

func cmdDelete(root string, args []string) int {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	force := fs.Bool("force", false, "kill the container if it is still running")
	fs.Parse(args)
	id := fs.Arg(0)
	s, err := loadState(root, id)
	if err != nil {
		if *force {
			return 0
		}
		die(err)
	}
	if alive(s.Pid) {
		if !*force {
			die(fmt.Errorf("container %q is still running", id))
		}
		syscall.Kill(s.Pid, syscall.SIGKILL)
	}
	os.RemoveAll(stateDir(root, id))
	return 0
}

// cmdFeatures prints the runtime features document an engine queries.
func cmdFeatures() int {
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"ociVersionMin": "1.0.0",
		"ociVersionMax": "1.2.0",
		"hooks":         []string{},
		"mountOptions":  []string{"rbind", "bind", "ro", "rw"},
		"annotations":   map[string]string{"org.laboon.runtime": "laboon"},
	})
	return 0
}

// lastArg returns the final non-flag argument (the container id).
func lastArg(args []string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !strings.HasPrefix(args[i], "-") {
			return args[i]
		}
	}
	return ""
}

func parseSignal(s string) syscall.Signal {
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	switch s {
	case "TERM":
		return syscall.SIGTERM
	case "KILL", "9":
		return syscall.SIGKILL
	case "INT", "2":
		return syscall.SIGINT
	case "HUP", "1":
		return syscall.SIGHUP
	case "QUIT", "3":
		return syscall.SIGQUIT
	case "USR1":
		return syscall.SIGUSR1
	case "USR2":
		return syscall.SIGUSR2
	case "15":
		return syscall.SIGTERM
	}
	if n, err := strconv.Atoi(s); err == nil {
		return syscall.Signal(n)
	}
	return 0
}
