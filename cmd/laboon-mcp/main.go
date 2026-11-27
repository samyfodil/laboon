// Command laboon-mcp exposes the laboon sandbox to AI agents over the Model
// Context Protocol. It offers one tool, "run", that executes a command inside
// an OCI image under laboon and returns its exit status and output, so an agent
// can run untrusted code without a VM or a second kernel.
//
// By default it speaks MCP over stdio, which is how Claude Desktop, Claude Code
// and most MCP clients launch a server:
//
//	laboon-mcp
//
// With -http it instead serves the streamable-HTTP transport, so one long-lived
// process can back many clients ("server mode"):
//
//	laboon-mcp -http :8080        # endpoint http://host:8080/
//
// Guest networking is off unless both -allow-net is given here and the caller
// asks for it, so a command cannot reach the network by default.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/samyfodil/laboon"
)

var version = "dev"

func main() {
	httpAddr := flag.String("http", "", "serve MCP over streamable HTTP at this address (e.g. :8080) instead of stdio")
	allowNet := flag.Bool("allow-net", false, "let the run tool enable guest networking when a caller asks for it")
	platform := flag.String("platform", "", "default image platform, linux/amd64 or linux/arm64 (default: host architecture)")
	maxOutput := flag.Int("max-output", 1<<20, "cap each of a run's captured stdout and stderr to this many bytes")
	defaultTimeout := flag.Int("default-timeout", 120, "per-run timeout in seconds when a caller does not set one (0 = none)")
	flag.Parse()

	srv := mcp.NewServer(&mcp.Implementation{Name: "laboon", Version: version}, nil)
	cfg := &toolConfig{allowNet: *allowNet, platform: *platform, maxOutput: *maxOutput, defaultTimeout: *defaultTimeout}
	mcp.AddTool(srv, &mcp.Tool{
		Name: "run",
		Description: "Run a command inside an OCI container image under the laboon sandbox and " +
			"return its exit code, stdout and stderr. Use it to execute untrusted or arbitrary " +
			"code safely: the program runs isolated from the host, with no network unless asked. " +
			"Example: image \"python:3.12-alpine\", command [\"python3\",\"-c\",\"print(2+2)\"].",
	}, cfg.run)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *httpAddr != "" {
		handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
		hs := &http.Server{Addr: *httpAddr, Handler: handler}
		go func() {
			<-ctx.Done()
			hs.Close()
		}()
		log.Printf("laboon-mcp serving MCP over HTTP at %s", *httpAddr)
		if err := hs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		return
	}
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}

type toolConfig struct {
	allowNet       bool
	platform       string
	maxOutput      int
	defaultTimeout int
}

// runInput is the "run" tool's arguments; the field tags become its JSON schema.
type runInput struct {
	Image          string   `json:"image" jsonschema:"OCI image reference to run, e.g. alpine:3.20 or python:3.12-alpine"`
	Command        []string `json:"command,omitempty" jsonschema:"command and arguments to run; replaces the image's default command (CMD). Omit to run the image's own entrypoint/CMD"`
	Stdin          string   `json:"stdin,omitempty" jsonschema:"data to feed the command on standard input"`
	Env            []string `json:"env,omitempty" jsonschema:"extra environment variables as KEY=VALUE entries"`
	Network        bool     `json:"network,omitempty" jsonschema:"allow the command to use the network (only honored if the server was started with -allow-net)"`
	Platform       string   `json:"platform,omitempty" jsonschema:"image platform, linux/amd64 or linux/arm64 (default: the server's)"`
	User           string   `json:"user,omitempty" jsonschema:"run as this user (uid, uid:gid, name or name:group), overriding the image's USER"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"kill the run after this many seconds (default: the server's)"`
}

// runOutput is the structured result of a "run" call.
type runOutput struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	TimedOut bool   `json:"timed_out,omitempty"`
}

func (c *toolConfig) run(ctx context.Context, _ *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, runOutput, error) {
	if strings.TrimSpace(in.Image) == "" {
		return nil, runOutput{}, fmt.Errorf("image is required")
	}

	var stdout, stderr capped
	stdout.limit, stderr.limit = c.maxOutput, c.maxOutput

	opts := []laboon.Option{laboon.WithStdout(&stdout), laboon.WithStderr(&stderr), laboon.WithCache(plans)}
	if len(in.Command) > 0 {
		opts = append(opts, laboon.WithArgs(in.Command...))
	}
	if in.Stdin != "" {
		opts = append(opts, laboon.WithStdin(strings.NewReader(in.Stdin)))
	}
	for _, e := range in.Env {
		opts = append(opts, laboon.WithEnv(e))
	}
	if in.Network && c.allowNet {
		opts = append(opts, laboon.WithNet())
	}
	if in.User != "" {
		opts = append(opts, laboon.WithUser(in.User))
	}
	if p := in.Platform; p != "" {
		opts = append(opts, laboon.WithPlatform(p))
	} else if c.platform != "" {
		opts = append(opts, laboon.WithPlatform(c.platform))
	}

	timeout := c.defaultTimeout
	if in.TimeoutSeconds > 0 {
		timeout = in.TimeoutSeconds
	}
	runCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	code, err := laboon.RunImage(runCtx, in.Image, opts...)
	timedOut := runCtx.Err() == context.DeadlineExceeded
	if err != nil && !timedOut {
		// A pull or setup failure, not a non-zero exit from the program.
		return nil, runOutput{}, fmt.Errorf("run %s: %w", in.Image, err)
	}

	out := runOutput{ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String(), TimedOut: timedOut}
	summary := fmt.Sprintf("exit code %d", code)
	if timedOut {
		summary = fmt.Sprintf("timed out after %ds", timeout)
	}
	if out.Stdout != "" {
		summary += "\n--- stdout ---\n" + out.Stdout
	}
	if out.Stderr != "" {
		summary += "\n--- stderr ---\n" + out.Stderr
	}
	res := &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: summary}},
		IsError: timedOut || code != 0,
	}
	return res, out, nil
}

// capped is an io.Writer that keeps at most limit bytes and counts the rest, so
// a runaway program cannot blow up the response.
type capped struct {
	mu      sync.Mutex
	limit   int
	buf     []byte
	dropped int
}

func (w *capped) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if room := w.limit - len(w.buf); room > 0 {
		if len(p) <= room {
			w.buf = append(w.buf, p...)
		} else {
			w.buf = append(w.buf, p[:room]...)
			w.dropped += len(p) - room
		}
	} else {
		w.dropped += len(p)
	}
	return len(p), nil
}

func (w *capped) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	s := string(w.buf)
	if w.dropped > 0 {
		s += fmt.Sprintf("\n... [%d more bytes truncated]", w.dropped)
	}
	return s
}

// plans keeps rewrite plans in the user cache directory, shared by every run
// in this process and by later processes.
var plans = planCache()

func planCache() *laboon.Cache {
	d, err := os.UserCacheDir()
	if err != nil {
		return laboon.NewCache("")
	}
	// Windows kept prepared images here, unbounded, before they moved
	// into the plan cache.
	os.RemoveAll(filepath.Join(d, "laboon", "img"))
	return laboon.NewCache(filepath.Join(d, "laboon", "plans"))
}
