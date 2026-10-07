package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/fakes"
	"github.com/render-oss/render-mcp-server/pkg/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testOwner = "tea-test123"

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx := session.ContextWithStdioSession(context.Background())
	require.NoError(t, session.FromContext(ctx).SetWorkspace(ctx, testOwner))
	return ctx
}

func callRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{Params: mcp.CallToolParams{Arguments: args}}
}

func resultText(t *testing.T, r *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, r.Content)
	return r.Content[0].(mcp.TextContent).Text
}

func ok(code int) *http.Response { return &http.Response{StatusCode: code} }

func TestToolsHaveAnnotationsAndShortNames(t *testing.T) {
	for _, tool := range Tools(&client.ClientWithResponses{}) {
		assert.LessOrEqual(t, len(tool.Tool.Name), 64, tool.Tool.Name)
		assert.NotEmpty(t, tool.Tool.Annotations.Title, tool.Tool.Name)
		require.NotNil(t, tool.Tool.Annotations.ReadOnlyHint, tool.Tool.Name)
		require.NotNil(t, tool.Tool.Annotations.DestructiveHint, tool.Tool.Name)
		if *tool.Tool.Annotations.ReadOnlyHint {
			assert.False(t, *tool.Tool.Annotations.DestructiveHint, tool.Tool.Name)
		}
	}
}

func TestWrapCommandQuotesSafely(t *testing.T) {
	got := wrapCommand(`echo 'hi' && echo "$HOME"`, 30)
	assert.Equal(t, `cd /root && timeout --kill-after=5 30 bash -c 'echo '"'"'hi'"'"' && echo "$HOME"'`, got)
}

func TestTruncateKeepsHeadAndTail(t *testing.T) {
	s := strings.Repeat("a", 30) + strings.Repeat("b", 30)
	out := truncate(s, 20)
	assert.True(t, strings.HasPrefix(out, strings.Repeat("a", 10)))
	assert.True(t, strings.HasSuffix(out, strings.Repeat("b", 10)))
	assert.Contains(t, out, "[40 characters truncated]")
	assert.Equal(t, "short", truncate("short", 20))
}

func TestReadSSE(t *testing.T) {
	stream := ": keep-alive\n\n" +
		"event: output\ndata: {\"stream\":\"stdout\",\"data\":\"line1\\n\"}\n\n" +
		"event: output\ndata: {\"stream\":\"stderr\",\"data\":\"warn\"}\n\n" +
		"event: exit\ndata: {\"exit_code\":3}\n\n" +
		"event: output\ndata: {\"stream\":\"stdout\",\"data\":\"ignored\"}\n\n"
	var seen []string
	err := readSSE(strings.NewReader(stream), func(event, data string) (bool, error) {
		seen = append(seen, event)
		return event == "exit", nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"output", "output", "exit"}, seen)

	err = readSSE(strings.NewReader("event: output\ndata: {}\n\n"), func(string, string) (bool, error) { return false, nil })
	assert.ErrorContains(t, err, "without an exit event")
}

func TestNetworkParams(t *testing.T) {
	policy, domains, err := networkParams(callRequest(map[string]any{}))
	require.NoError(t, err)
	assert.Equal(t, sbx.AllowAll, policy)
	assert.Empty(t, domains)

	policy, domains, err = networkParams(callRequest(map[string]any{
		"network": "allow-list", "allowedDomains": []any{"pypi.org", "*.pythonhosted.org"}}))
	require.NoError(t, err)
	assert.Equal(t, sbx.AllowList, policy)
	assert.Equal(t, []string{"pypi.org", "*.pythonhosted.org"}, domains)

	_, _, err = networkParams(callRequest(map[string]any{"network": "allow-list"}))
	assert.ErrorContains(t, err, "allowedDomains is required")
	_, _, err = networkParams(callRequest(map[string]any{"network": "deny-all", "allowedDomains": []any{"x.com"}}))
	assert.ErrorContains(t, err, "only applies")
	_, _, err = networkParams(callRequest(map[string]any{"network": "open"}))
	assert.ErrorContains(t, err, "must be one of")
}

func TestCreateSandboxScopesToWorkspaceAndWaits(t *testing.T) {
	fake := &fakes.FakeSandboxRepoClient{}
	fake.CreateSandboxWithResponseReturns(&client.CreateSandboxResponse{
		HTTPResponse: ok(201), JSON201: &sbx.Sandbox{Id: "sbx-1", Status: "creating"}}, nil)
	fake.RetrieveSandboxWithResponseReturnsOnCall(0, &client.RetrieveSandboxResponse{
		HTTPResponse: ok(200), JSON200: &sbx.Sandbox{Id: "sbx-1", Status: "creating"}}, nil)
	fake.RetrieveSandboxWithResponseReturnsOnCall(1, &client.RetrieveSandboxResponse{
		HTTPResponse: ok(200), JSON200: &sbx.Sandbox{Id: "sbx-1", Status: "running",
			NetworkPolicy: sbx.SandboxNetworkPolicy{Default: sbx.AllowList, AllowedDomains: &[]string{"pypi.org"}}}}, nil)
	repo := NewRepo(fake)
	repo.pollEvery = time.Millisecond

	res, err := createSandbox(repo).Handler(testContext(t), callRequest(map[string]any{
		"lifetimeSeconds": float64(10), "network": "allow-list", "allowedDomains": []any{"pypi.org"},
		"snapshot": "py-base", "env": map[string]any{"MODE": "test"}}))
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(t, res))

	_, body, _ := fake.CreateSandboxWithResponseArgsForCall(0)
	assert.Equal(t, testOwner, body.OwnerId)
	assert.Equal(t, 60, *body.TimeoutSeconds, "lifetime is clamped to at least 60s")
	assert.Equal(t, sbx.AllowList, body.NetworkPolicy.Default)
	assert.Equal(t, []string{"pypi.org"}, *body.NetworkPolicy.AllowedDomains)
	assert.Equal(t, "py-base", *body.SnapshotName)
	assert.Nil(t, body.SnapshotId)
	assert.Equal(t, map[string]string{"MODE": "test"}, *body.Env)
	_, _, params, _ := fake.RetrieveSandboxWithResponseArgsForCall(1)
	assert.Equal(t, testOwner, *params.OwnerId)

	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(resultText(t, res)), &out))
	assert.Equal(t, "sbx-1", out["sandboxId"])
	assert.Equal(t, "running", out["status"])
}

func TestCreateSandboxTerminatesWhenItErrors(t *testing.T) {
	fake := &fakes.FakeSandboxRepoClient{}
	fake.CreateSandboxWithResponseReturns(&client.CreateSandboxResponse{
		HTTPResponse: ok(201), JSON201: &sbx.Sandbox{Id: "sbx-2", Status: "creating"}}, nil)
	fake.RetrieveSandboxWithResponseReturns(&client.RetrieveSandboxResponse{
		HTTPResponse: ok(200), JSON200: &sbx.Sandbox{Id: "sbx-2", Status: "errored"}}, nil)
	fake.TerminateSandboxWithResponseReturns(&client.TerminateSandboxResponse{HTTPResponse: ok(204)}, nil)
	repo := NewRepo(fake)

	res, err := createSandbox(repo).Handler(testContext(t), callRequest(map[string]any{}))
	require.NoError(t, err)
	assert.True(t, res.IsError)
	assert.Contains(t, resultText(t, res), "errored")
	assert.Equal(t, 1, fake.TerminateSandboxWithResponseCallCount())
}

func TestRunSandboxCommandStreamsFromSandboxHost(t *testing.T) {
	var gotAuth, gotCommand string
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotCommand = body["command"]
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: output\ndata: {\"stream\":\"stdout\",\"data\":\"42\\n\"}\n\n"+
			"event: output\ndata: {\"stream\":\"stderr\",\"data\":\"careful\"}\n\n"+
			"event: exit\ndata: {\"exit_code\":0}\n\n")
	}))
	defer host.Close()

	fake := &fakes.FakeSandboxRepoClient{}
	fake.ConnectSandboxRunWithResponseReturns(&client.ConnectSandboxRunResponse{
		HTTPResponse: ok(201),
		JSON201:      &sbx.SandboxConnectResponse{Token: "run-token", Uri: host.URL + "/runs/stream", Method: "POST"},
	}, nil)
	repo := NewRepo(fake)

	res, err := runSandboxCommand(repo).Handler(testContext(t), callRequest(map[string]any{
		"sandboxId": "sbx-3", "command": "python3 -c 'print(6*7)'", "timeoutSeconds": float64(9999)}))
	require.NoError(t, err)
	require.False(t, res.IsError, resultText(t, res))

	assert.Equal(t, "Bearer run-token", gotAuth)
	assert.Equal(t, `cd /root && timeout --kill-after=5 600 bash -c 'python3 -c '"'"'print(6*7)'"'"''`, gotCommand,
		"timeout is clamped to 600 and the command is quoted")
	_, id, op, params, body, _ := fake.ConnectSandboxRunWithResponseArgsForCall(0)
	assert.Equal(t, "sbx-3", id)
	assert.Equal(t, "stream", op)
	assert.Equal(t, testOwner, *params.OwnerId)
	assert.Equal(t, gotCommand, *body.Command)

	var out ExecResult
	require.NoError(t, json.Unmarshal([]byte(resultText(t, res)), &out))
	assert.Equal(t, 0, *out.ExitCode)
	assert.False(t, out.TimedOut)
	assert.Equal(t, "42\n", out.Stdout)
	assert.Equal(t, "careful", out.Stderr)
}

func TestReadSandboxFileHandlesMissingAndDirectories(t *testing.T) {
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("path") {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/dir":
			w.Header().Set("Content-Type", "application/x-tar")
			_, _ = w.Write([]byte("tar"))
		default:
			_, _ = w.Write([]byte("hello world"))
		}
	}))
	defer host.Close()
	fake := &fakes.FakeSandboxRepoClient{}
	fake.ConnectSandboxFilesWithResponseStub = func(_ context.Context, _ string, _ string, p *client.ConnectSandboxFilesParams, _ ...client.RequestEditorFn) (*client.ConnectSandboxFilesResponse, error) {
		return &client.ConnectSandboxFilesResponse{HTTPResponse: ok(201), JSON201: &sbx.SandboxConnectResponse{
			Token: "t", Method: "GET", Uri: host.URL + "/files/download?path=" + p.Path}}, nil
	}
	repo := NewRepo(fake)
	tool := readSandboxFile(repo)

	res, _ := tool.Handler(testContext(t), callRequest(map[string]any{"sandboxId": "sbx-4", "path": "/f", "maxBytes": float64(5)}))
	require.False(t, res.IsError, resultText(t, res))
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(resultText(t, res)), &out))
	assert.Equal(t, "hello", out["content"])
	assert.Equal(t, true, out["truncated"])

	res, _ = tool.Handler(testContext(t), callRequest(map[string]any{"sandboxId": "sbx-4", "path": "/missing"}))
	assert.True(t, res.IsError)
	assert.Contains(t, resultText(t, res), "file not found")

	res, _ = tool.Handler(testContext(t), callRequest(map[string]any{"sandboxId": "sbx-4", "path": "/dir"}))
	assert.True(t, res.IsError)
	assert.Contains(t, resultText(t, res), "directory")
}

func TestOneShotReportsCleanupOutcome(t *testing.T) {
	for _, cleanupFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("cleanupFails=%t", cleanupFails), func(t *testing.T) {
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "event: output\ndata: {\"stream\":\"stdout\",\"data\":\"verified\"}\n\nevent: exit\ndata: {\"exit_code\":0}\n\n")
			}))
			defer host.Close()
			fake := &fakes.FakeSandboxRepoClient{}
			fake.CreateSandboxWithResponseReturns(&client.CreateSandboxResponse{HTTPResponse: ok(201), JSON201: &sbx.Sandbox{Id: "sbx-cleanup"}}, nil)
			fake.RetrieveSandboxWithResponseReturns(&client.RetrieveSandboxResponse{HTTPResponse: ok(200), JSON200: &sbx.Sandbox{Id: "sbx-cleanup", Status: "running"}}, nil)
			fake.ConnectSandboxRunWithResponseReturns(&client.ConnectSandboxRunResponse{HTTPResponse: ok(201), JSON201: &sbx.SandboxConnectResponse{Uri: host.URL, Method: "POST", Token: "test"}}, nil)
			fake.TerminateSandboxWithResponseStub = func(ctx context.Context, id string, params *client.TerminateSandboxParams, editors ...client.RequestEditorFn) (*client.TerminateSandboxResponse, error) {
				require.NoError(t, ctx.Err())
				_, bounded := ctx.Deadline()
				assert.True(t, bounded, "cleanup must be bounded")
				if cleanupFails {
					return nil, errors.New("cleanup unavailable")
				}
				return &client.TerminateSandboxResponse{HTTPResponse: ok(204)}, nil
			}
			result, err := runInNewSandbox(NewRepo(fake)).Handler(testContext(t), callRequest(map[string]any{"command": "echo verified"}))
			require.NoError(t, err)
			var out map[string]any
			require.NoError(t, json.Unmarshal([]byte(resultText(t, result)), &out))
			assert.Equal(t, "sbx-cleanup", out["sandboxId"])
			assert.Equal(t, "verified", out["stdout"])
			assert.Equal(t, !cleanupFails, out["terminated"])
			assert.Equal(t, cleanupFails, result.IsError)
			if cleanupFails {
				assert.Contains(t, out["cleanupError"], "cleanup unavailable")
			}
			assert.Equal(t, 1, fake.TerminateSandboxWithResponseCallCount())
		})
	}
}

func TestOneShotCleansUpAfterExecutionError(t *testing.T) {
	fake := &fakes.FakeSandboxRepoClient{}
	fake.CreateSandboxWithResponseReturns(&client.CreateSandboxResponse{HTTPResponse: ok(201), JSON201: &sbx.Sandbox{Id: "sbx-cancel"}}, nil)
	fake.RetrieveSandboxWithResponseReturns(&client.RetrieveSandboxResponse{HTTPResponse: ok(200), JSON200: &sbx.Sandbox{Id: "sbx-cancel", Status: "running"}}, nil)
	ctx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	fake.ConnectSandboxRunWithResponseStub = func(_ context.Context, id string, operation string, params *client.ConnectSandboxRunParams, body client.ConnectSandboxRunJSONRequestBody, editors ...client.RequestEditorFn) (*client.ConnectSandboxRunResponse, error) {
		cancel()
		return nil, context.Canceled
	}
	fake.TerminateSandboxWithResponseStub = func(cleanupCtx context.Context, id string, params *client.TerminateSandboxParams, editors ...client.RequestEditorFn) (*client.TerminateSandboxResponse, error) {
		assert.NoError(t, cleanupCtx.Err(), "caller cancellation must not prevent cleanup")
		assert.Equal(t, "sbx-cancel", id)
		assert.Equal(t, testOwner, *params.OwnerId)
		_, bounded := cleanupCtx.Deadline()
		assert.True(t, bounded)
		return &client.TerminateSandboxResponse{HTTPResponse: ok(204)}, nil
	}
	result, err := runInNewSandbox(NewRepo(fake)).Handler(ctx, callRequest(map[string]any{"command": "echo test"}))
	require.NoError(t, err)
	require.True(t, result.IsError)
	var out map[string]any
	require.NoError(t, json.Unmarshal([]byte(resultText(t, result)), &out))
	assert.Equal(t, "sbx-cancel", out["sandboxId"])
	assert.Equal(t, true, out["terminated"])
	assert.Contains(t, out["error"], "context canceled")
	assert.Equal(t, 1, fake.TerminateSandboxWithResponseCallCount())
}
