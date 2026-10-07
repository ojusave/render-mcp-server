// Package sandbox exposes Render Sandboxes as MCP tools: isolated Linux microVMs
// where Claude can run commands and move files without touching the user's machine.
package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/pointers"
	"github.com/render-oss/render-mcp-server/pkg/validate"
)

const (
	maxOutputChars        = 20_000
	defaultCommandSeconds = 120
	maxCommandSeconds     = 600
	defaultLifetime       = 1800
	maxLifetime           = 86_400
	defaultReadBytes      = 50_000
	maxReadBytes          = 200_000
)

const sandboxIDDescription = "The sbx-... ID returned by create_sandbox or list_sandboxes"

func Tools(c *client.ClientWithResponses) []server.ServerTool {
	repo := NewRepo(c)
	return []server.ServerTool{
		runInNewSandbox(repo),
		createSandbox(repo),
		runSandboxCommand(repo),
		writeSandboxFile(repo),
		readSandboxFile(repo),
		listSandboxFiles(repo),
		listSandboxes(repo),
		snapshotSandbox(repo),
		listSandboxSnapshots(repo),
		terminateSandbox(repo),
	}
}

func annotations(title string, readOnly, destructive, idempotent, openWorld bool) mcp.ToolOption {
	return mcp.WithToolAnnotation(mcp.ToolAnnotation{
		Title:           title,
		ReadOnlyHint:    pointers.From(readOnly),
		DestructiveHint: pointers.From(destructive),
		IdempotentHint:  pointers.From(idempotent),
		OpenWorldHint:   pointers.From(openWorld),
	})
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func truncate(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	half := limit / 2
	head, tail := s[:half], s[len(s)-half:]
	for !utf8.ValidString(head) && len(head) > 0 {
		head = head[:len(head)-1]
	}
	for !utf8.ValidString(tail) && len(tail) > 0 {
		tail = tail[1:]
	}
	return fmt.Sprintf("%s\n... [%d characters truncated] ...\n%s", head, len(s)-len(head)-len(tail), tail)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// wrapCommand starts every command in /root and enforces the timeout inside the
// sandbox, so a runaway process is actually stopped.
func wrapCommand(command string, seconds int) string {
	return fmt.Sprintf("cd /root && timeout --kill-after=5 %d bash -c %s", seconds, shellQuote(command))
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func intParam(request mcp.CallToolRequest, name string, def int) (int, error) {
	v, ok, err := validate.OptionalToolParam[float64](request, name)
	if err != nil {
		return 0, err
	}
	if !ok {
		return def, nil
	}
	return int(v), nil
}

func stringMapParam(request mcp.CallToolRequest, name string) (map[string]string, error) {
	raw, ok, err := validate.OptionalToolParam[map[string]any](request, name)
	if err != nil || !ok {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		s, isString := v.(string)
		if !isString {
			return nil, fmt.Errorf("%s.%s must be a string", name, k)
		}
		out[k] = s
	}
	return out, nil
}

// networkParams reads the shared network options.
func networkParams(request mcp.CallToolRequest) (sbx.SandboxNetworkPolicyDefault, []string, error) {
	network, ok, err := validate.OptionalToolParam[string](request, "network")
	if err != nil {
		return "", nil, err
	}
	if !ok {
		network = string(sbx.AllowAll)
	}
	policy := sbx.SandboxNetworkPolicyDefault(network)
	if !policy.Valid() {
		return "", nil, fmt.Errorf("network must be one of allow-all, deny-all, allow-list")
	}
	domains, _, err := validate.OptionalToolArrayParam[string](request, "allowedDomains")
	if err != nil {
		return "", nil, err
	}
	if policy == sbx.AllowList && len(domains) == 0 {
		return "", nil, errors.New("allowedDomains is required when network is allow-list")
	}
	if policy != sbx.AllowList && len(domains) > 0 {
		return "", nil, errors.New("allowedDomains only applies when network is allow-list")
	}
	return policy, domains, nil
}

var networkOptions = []mcp.ToolOption{
	mcp.WithString("network",
		mcp.Description("Outbound network access: allow-all (default), deny-all, or allow-list. "+
			"Use deny-all for untrusted code that needs no internet."),
		mcp.Enum(string(sbx.AllowAll), string(sbx.DenyAll), string(sbx.AllowList)),
	),
	mcp.WithArray("allowedDomains",
		mcp.Description("With network=allow-list, the only domains the sandbox may reach over HTTP and HTTPS, "+
			"for example [\"pypi.org\", \"*.pythonhosted.org\"]. Matching is exact; a leading *. matches subdomains."),
		mcp.WithStringItems(),
	),
}

func sandboxSummary(s sbx.Sandbox) map[string]any {
	out := map[string]any{
		"sandboxId":      s.Id,
		"status":         s.Status,
		"createdAt":      s.CreatedAt,
		"timeoutSeconds": s.TimeoutSeconds,
		"network":        s.NetworkPolicy.Default,
	}
	if s.NetworkPolicy.AllowedDomains != nil {
		out["allowedDomains"] = *s.NetworkPolicy.AllowedDomains
	}
	return out
}

func createSandbox(repo *Repo) server.ServerTool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("Create a fresh, isolated Linux sandbox (a Render Sandbox microVM) and wait until it is ready, " +
			"usually in a few seconds. Sandboxes run Debian 12 on x86_64 as root, with bash, curl, git, python3, and node. " +
			"Use one to run code that should not touch the user's machine. Terminate it with terminate_sandbox when done."),
		annotations("Create sandbox", false, false, false, true),
		mcp.WithNumber("lifetimeSeconds",
			mcp.Description("Hard limit before Render terminates the sandbox. Default 1800, max 86400."),
			mcp.DefaultNumber(defaultLifetime),
		),
		mcp.WithString("snapshot",
			mcp.Description("Optional snapshot ID (snp-...) or name to start from instead of the base image."),
		),
		mcp.WithObject("env",
			mcp.Description("Optional environment variables, as string keys and values, visible to every command."),
		),
	}
	opts = append(opts, networkOptions...)
	return server.ServerTool{
		Tool: mcp.NewTool("create_sandbox", opts...),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			lifetime, err := intParam(request, "lifetimeSeconds", defaultLifetime)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			network, domains, err := networkParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			snapshot, _, err := validate.OptionalToolParam[string](request, "snapshot")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			env, err := stringMapParam(request, "env")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			s, err := repo.Create(ctx, CreateInput{
				TimeoutSeconds: clamp(lifetime, 60, maxLifetime),
				Network:        network,
				AllowedDomains: domains,
				Snapshot:       snapshot,
				Env:            env,
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			out := sandboxSummary(*s)
			out["workingDirectory"] = "/root"
			return jsonResult(out)
		},
	}
}

func runSandboxCommand(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("run_sandbox_command",
			mcp.WithDescription("Run a bash command in a sandbox and return stdout, stderr, and the exit code. "+
				"Each call starts a new shell in /root, so cd does not persist; chain steps with && or use absolute paths. "+
				"A non-zero exit code is a normal result. Output over 20,000 characters is truncated in the middle."),
			annotations("Run sandbox command", false, true, false, true),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
			mcp.WithString("command", mcp.Required(),
				mcp.Description("Bash command line, for example \"python3 -m venv v && v/bin/pip install requests\"")),
			mcp.WithNumber("timeoutSeconds",
				mcp.Description("Stop the command after this many seconds. Default 120, max 600."),
				mcp.DefaultNumber(defaultCommandSeconds)),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			command, err := validate.RequiredToolParam[string](request, "command")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			seconds, err := intParam(request, "timeoutSeconds", defaultCommandSeconds)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			seconds = clamp(seconds, 1, maxCommandSeconds)
			res, err := repo.Exec(ctx, id, wrapCommand(command, seconds), time.Duration(seconds)*time.Second)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(res)
		},
	}
}

func writeSandboxFile(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("write_sandbox_file",
			mcp.WithDescription("Create or overwrite a text file in a sandbox. Parent directories are created."),
			annotations("Write sandbox file", false, true, true, false),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
			mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path, or a path relative to /root")),
			mcp.WithString("content", mcp.Required(), mcp.Description("Full file contents")),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, err := validate.RequiredToolParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			content, err := validate.RequiredToolParam[string](request, "content")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if err := repo.WriteFile(ctx, id, path, []byte(content)); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(map[string]any{"sandboxId": id, "path": path, "bytes": len(content)})
		},
	}
}

func readSandboxFile(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("read_sandbox_file",
			mcp.WithDescription("Read a text file from a sandbox."),
			annotations("Read sandbox file", true, false, true, false),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
			mcp.WithString("path", mcp.Required(), mcp.Description("Absolute path, or a path relative to /root")),
			mcp.WithNumber("maxBytes",
				mcp.Description("Return at most this many bytes. Default 50000, max 200000."),
				mcp.DefaultNumber(defaultReadBytes)),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, err := validate.RequiredToolParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			maxBytes, err := intParam(request, "maxBytes", defaultReadBytes)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			limit := int64(clamp(maxBytes, 1, maxReadBytes))
			data, size, err := repo.ReadFile(ctx, id, path, limit)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("%s: %s", path, err.Error())), nil
			}
			return jsonResult(map[string]any{
				"sandboxId": id, "path": path, "sizeBytes": size, "truncated": size > limit,
				"content": strings.ToValidUTF8(string(data), "�"),
			})
		},
	}
}

func listSandboxFiles(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_sandbox_files",
			mcp.WithDescription("List the files and directories directly inside a directory in a sandbox."),
			annotations("List sandbox files", true, false, true, false),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
			mcp.WithString("path", mcp.Description("Absolute directory path. Default /root."), mcp.DefaultString("/root")),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			path, _, err := validate.OptionalToolParam[string](request, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			dir, entries, err := repo.ListFiles(ctx, id, path)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(map[string]any{"path": dir, "entries": entries})
		},
	}
}

func listSandboxes(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_sandboxes",
			mcp.WithDescription("List sandboxes in the workspace, newest first. Terminated sandboxes are left out unless requested."),
			annotations("List sandboxes", true, false, true, false),
			mcp.WithBoolean("includeTerminated", mcp.Description("Include terminated sandboxes. Default false.")),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			include, _, err := validate.OptionalToolParam[bool](request, "includeTerminated")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			items, err := repo.List(ctx, include)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(items) == 0 {
				return mcp.NewToolResultText("No sandboxes found"), nil
			}
			out := make([]map[string]any, 0, len(items))
			for _, s := range items {
				out = append(out, sandboxSummary(s))
			}
			return jsonResult(out)
		},
	}
}

func snapshotSandbox(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("snapshot_sandbox",
			mcp.WithDescription("Save a running sandbox's filesystem so new sandboxes can start from it with create_sandbox. "+
				"The sandbox keeps running. Snapshots expire after three days by default."),
			annotations("Snapshot sandbox", false, false, false, false),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
			mcp.WithString("name", mcp.Description("Optional name to restore by, such as \"python-ml-base\"")),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			name, _, err := validate.OptionalToolParam[string](request, "name")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			snap, err := repo.Snapshot(ctx, id, name)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(snap)
		},
	}
}

func listSandboxSnapshots(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("list_sandbox_snapshots",
			mcp.WithDescription("List sandbox snapshots in the workspace that are available to restore."),
			annotations("List sandbox snapshots", true, false, true, false),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			snaps, err := repo.ListSnapshots(ctx)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(snaps) == 0 {
				return mcp.NewToolResultText("No available snapshots"), nil
			}
			return jsonResult(snaps)
		},
	}
}

func terminateSandbox(repo *Repo) server.ServerTool {
	return server.ServerTool{
		Tool: mcp.NewTool("terminate_sandbox",
			mcp.WithDescription("Terminate a sandbox and permanently delete its filesystem."),
			annotations("Terminate sandbox", false, true, true, false),
			mcp.WithString("sandboxId", mcp.Required(), mcp.Description(sandboxIDDescription)),
		),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := validate.RequiredToolParam[string](request, "sandboxId")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if err := repo.Terminate(ctx, id); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(map[string]any{"sandboxId": id, "status": "terminated"})
		},
	}
}

func runInNewSandbox(repo *Repo) server.ServerTool {
	opts := []mcp.ToolOption{
		mcp.WithDescription("One step: create a sandbox, write any files, run one bash command, return the output, " +
			"and terminate the sandbox. Use for quick jobs such as running a script on a clean Linux machine."),
		annotations("Run in new sandbox", false, false, false, true),
		mcp.WithString("command", mcp.Required(), mcp.Description("Bash command to run, starting in /root")),
		mcp.WithObject("files",
			mcp.Description("Optional map of file path to text content, written before the command runs")),
		mcp.WithNumber("timeoutSeconds",
			mcp.Description("Stop the command after this many seconds. Default 120, max 600."),
			mcp.DefaultNumber(defaultCommandSeconds)),
	}
	opts = append(opts, networkOptions...)
	return server.ServerTool{
		Tool: mcp.NewTool("run_in_new_sandbox", opts...),
		Handler: func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			command, err := validate.RequiredToolParam[string](request, "command")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			files, err := stringMapParam(request, "files")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			seconds, err := intParam(request, "timeoutSeconds", defaultCommandSeconds)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			seconds = clamp(seconds, 1, maxCommandSeconds)
			network, domains, err := networkParams(request)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			s, err := repo.Create(ctx, CreateInput{
				TimeoutSeconds: seconds + 300, Network: network, AllowedDomains: domains,
			})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			// Always clean up, even if the caller's context is cancelled.
			defer func() { _ = repo.Terminate(context.WithoutCancel(ctx), s.Id) }()
			for path, content := range files {
				if err := repo.WriteFile(ctx, s.Id, path, []byte(content)); err != nil {
					return mcp.NewToolResultError(fmt.Sprintf("writing %s: %s", path, err.Error())), nil
				}
			}
			res, err := repo.Exec(ctx, s.Id, wrapCommand(command, seconds), time.Duration(seconds)*time.Second)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return jsonResult(map[string]any{
				"sandboxId": s.Id, "terminated": true, "exitCode": res.ExitCode, "timedOut": res.TimedOut,
				"durationSeconds": res.DurationSeconds, "stdout": res.Stdout, "stderr": res.Stderr,
			})
		},
	}
}
