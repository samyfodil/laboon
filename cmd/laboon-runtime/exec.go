package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/samyfodil/laboon"
)

// cmdExec runs a new process in an existing container (docker exec). The command
// runs in the container's root filesystem; it is a fresh laboon sandbox over the
// same rootfs rather than a process injected into the running one's namespaces.
func cmdExec(root string, args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	processFile := fs.String("process", "", "path to the process spec JSON")
	consoleSocket := fs.String("console-socket", "", "socket to pass the terminal master to")
	detach := fs.Bool("detach", false, "run detached")
	fs.Bool("d", false, "run detached")
	pidFile := fs.String("pid-file", "", "write the exec pid here")
	fs.Parse(args)
	id := fs.Arg(0)
	s, err := loadState(root, id)
	if err != nil {
		die(err)
	}
	if *processFile == "" {
		die(fmt.Errorf("exec: --process is required"))
	}

	stdin, stdout, stderr := (*os.File)(os.Stdin), os.Stdout, os.Stderr
	if *consoleSocket != "" {
		slave, err := setupConsole(*consoleSocket)
		if err != nil {
			die(err)
		}
		stdin, stdout, stderr = slave, slave, slave
	}
	if *detach {
		// Copy the process spec: the engine deletes its --process temp file once
		// exec returns, before the detached process gets to read it.
		pf, err := copyToState(root, id, *processFile)
		if err != nil {
			die(err)
		}
		self, _ := os.Executable()
		cmd := exec.Command(self, "__exec", s.Rootfs, pf)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			die(err)
		}
		if *pidFile != "" {
			os.WriteFile(*pidFile, []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
		}
		cmd.Process.Release()
		return 0
	}
	return runExec(s.Rootfs, *processFile, stdin, stdout, stderr)
}

// cmdExecRun is the detached exec process: it runs the exec command and exits
// with its status for the engine to reap. Not user-facing.
func cmdExecRun(args []string) int {
	if len(args) < 2 {
		return 1
	}
	return runExec(args[0], args[1], os.Stdin, os.Stdout, os.Stderr)
}

func runExec(rootfs, processFile string, stdin *os.File, stdout, stderr *os.File) int {
	p, err := loadProcess(processFile)
	if err != nil {
		die(err)
	}
	prog, opts := procOptions(p, rootfs, stdin, stdout, stderr)
	code, err := laboon.Run(context.Background(), prog, opts...)
	plans.Sync()
	if err != nil {
		die(err)
	}
	return code
}

// copyToState copies the process spec into the container's state dir so the
// detached exec can read it after the engine removes its own temp file.
func copyToState(root, id, src string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(stateDir(root, id), "exec-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

func loadProcess(path string) (*Process, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Process
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("process spec: %w", err)
	}
	if len(p.Args) == 0 {
		return nil, fmt.Errorf("process spec: no args")
	}
	return &p, nil
}
