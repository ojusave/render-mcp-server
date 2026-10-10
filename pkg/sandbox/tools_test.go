package sandbox

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
)

func TestInvalidArgumentsHaveNoSideEffects(t *testing.T) {
	tests := []struct {
		name, tool string
		args       map[string]any
	}{
		{"fraction", "create_sandbox", map[string]any{"timeout_seconds": 1.5}},
		{"nan", "create_sandbox", map[string]any{"timeout_seconds": math.NaN()}},
		{"infinity", "create_sandbox", map[string]any{"timeout_seconds": math.Inf(1)}},
		{"wrong type", "create_sandbox", map[string]any{"timeout_seconds": "600"}},
		{"negative", "create_sandbox", map[string]any{"timeout_seconds": float64(-1)}},
		{"over max", "create_sandbox", map[string]any{"timeout_seconds": float64(86401)}},
		{"unknown policy", "create_sandbox", map[string]any{"network_policy": "default"}},
		{"empty allow list", "create_sandbox", map[string]any{"network_policy": "allow-list"}},
		{"ignored domains", "create_sandbox", map[string]any{"network_policy": "deny-all", "allowed_domains": []any{}}},
		{"url domain", "create_sandbox", map[string]any{"network_policy": "allow-list", "allowed_domains": []any{"https://example.com"}}},
		{"duplicate domain", "create_sandbox", map[string]any{"network_policy": "allow-list", "allowed_domains": []any{"example.com", "EXAMPLE.com"}}},
		{"invalid wildcard", "create_sandbox", map[string]any{"network_policy": "allow-list", "allowed_domains": []any{"foo.*.com"}}},
		{"wrong plan", "create_sandbox", map[string]any{"plan": "free"}},
		{"ignored parameter", "create_sandbox", map[string]any{"networkPolicy": "deny-all"}},
		{"bad id", "get_sandbox", map[string]any{"sandboxId": "sbx-a/../../other"}},
		{"empty command", "run_sandbox_command", map[string]any{"sandboxId": "sbx-a", "command": "  "}},
		{"huge command", "run_sandbox_command", map[string]any{"sandboxId": "sbx-a", "command": strings.Repeat("x", maxCommandBytes+1)}},
		{"long wait", "run_sandbox_command", map[string]any{"sandboxId": "sbx-a", "command": "true", "wait_timeout_seconds": float64(31)}},
		{"legacy timeout", "run_sandbox_command", map[string]any{"sandboxId": "sbx-a", "command": "true", "timeout_seconds": float64(600)}},
		{"path traversal", "read_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "../file"}},
		{"path clean", "read_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "/tmp/../file"}},
		{"missing content", "write_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "/tmp/file"}},
		{"huge content", "write_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "/tmp/file", "content": strings.Repeat("é", maxFileBytes)}},
		{"nul content", "write_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "/tmp/file", "content": "a\x00b"}},
		{"unknown status", "list_sandboxes", map[string]any{"statuses": []any{"success"}}},
		{"bad page", "list_sandboxes", map[string]any{"limit": 0.5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, f := newFixture(t)
			result := call(t, r, tt.tool, tt.args)
			require.True(t, result.IsError, text(t, result))
			require.Empty(t, f.calls)
			require.Zero(t, f.proxyCalls)
		})
	}
}

func TestDefaultsAndEmptyFile(t *testing.T) {
	r, f := newFixture(t)
	require.False(t, call(t, r, "create_sandbox", nil).IsError)
	require.Contains(t, f.calls[0].Body, `"type":"deny-all"`)
	require.NotContains(t, f.calls[0].Body, "rules")
	result := call(t, r, "write_sandbox_file", map[string]any{"sandboxId": "sbx-a", "path": "/tmp/empty", "content": ""})
	require.False(t, result.IsError, text(t, result))
	require.Contains(t, text(t, result), `"bytes":0`)
}

func TestToolAnnotations(t *testing.T) {
	tools := Tools(nil)
	require.Len(t, tools, 7)
	for _, tool := range tools {
		readOnly := tool.Tool.Name == "get_sandbox" || tool.Tool.Name == "list_sandboxes" || tool.Tool.Name == "read_sandbox_file"
		require.Equal(t, readOnly, *tool.Tool.Annotations.ReadOnlyHint, tool.Tool.Name)
		if tool.Tool.Name == "run_sandbox_command" || tool.Tool.Name == "write_sandbox_file" {
			require.True(t, *tool.Tool.Annotations.DestructiveHint)
			require.False(t, *tool.Tool.Annotations.IdempotentHint)
		}
	}
}

func TestBoundIncludesWrappedHandlerAndRejectsExcessConcurrency(t *testing.T) {
	entered := make(chan struct{}, maxConcurrentCalls)
	release := make(chan struct{})
	tools := WithLimits([]server.ServerTool{{Tool: mcp.NewTool("test"), Handler: func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), handlerTimeout)
		entered <- struct{}{}
		<-release
		return mcp.NewToolResultText("done"), nil
	}}})
	var wg sync.WaitGroup
	for range maxConcurrentCalls {
		wg.Go(func() { _, err := tools[0].Handler(t.Context(), mcp.CallToolRequest{}); require.NoError(t, err) })
	}
	for range maxConcurrentCalls {
		<-entered
	}
	result, err := tools[0].Handler(t.Context(), mcp.CallToolRequest{})
	require.NoError(t, err)
	require.True(t, result.IsError)
	require.Contains(t, text(t, result), "no operation started")
	close(release)
	wg.Wait()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	result, err = tools[0].Handler(ctx, mcp.CallToolRequest{})
	require.NoError(t, err)
	require.True(t, result.IsError)
}

func TestResultKeepsExecutionIDOnSetupError(t *testing.T) {
	r, f := newFixture(t)
	f.tokenURI = "https://attacker.test"
	result := call(t, r, "run_sandbox_command", map[string]any{"sandboxId": "sbx-a", "command": "true"})
	require.True(t, result.IsError)
	require.Contains(t, text(t, result), "exe-test")
	require.NotContains(t, text(t, result), "SCOPED_SECRET")
	require.NotContains(t, text(t, result), "ACCOUNT_SECRET")
}
