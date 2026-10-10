package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/render-oss/render-mcp-server/pkg/authn"
	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/session"
	"github.com/stretchr/testify/require"
)

type doer func(*http.Request) (*http.Response, error)

func (f doer) Do(req *http.Request) (*http.Response, error)        { return f(req) }
func (f doer) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func response(code int, kind, body string) *http.Response {
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {kind}}, Body: io.NopCloser(strings.NewReader(body))}
}

type recordedCall struct {
	Method, Path, Owner string
	Query               url.Values
	Body                string
	Auth                string
}
type fixture struct {
	mu               sync.Mutex
	calls            []recordedCall
	proxyCalls       int
	statusCode       int
	terminationState string
	initialState     string
	stream           string
	fileBody         string
	fileType         string
	proxyStatus      int
	tokenURI         string
}

func newFixture(t *testing.T) (*Repo, *fixture) {
	t.Helper()
	f := &fixture{statusCode: 200, terminationState: "terminated", stream: "event: exit\ndata: {\"exit_code\":0}\n\n", fileBody: "hello", fileType: "application/octet-stream", proxyStatus: 200}
	c, err := client.NewClientWithResponses("https://api.example.test/v1", client.WithHTTPClient(doer(f.api)), client.WithRequestEditorFn(func(ctx context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+authn.APITokenFromContext(ctx))
		return nil
	}))
	require.NoError(t, err)
	repo := NewRepo(c)
	repo.proxy.Transport = doer(f.proxy)
	return repo, f
}

func (f *fixture) api(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	f.calls = append(f.calls, recordedCall{req.Method, req.URL.Path, req.URL.Query().Get("ownerId"), req.URL.Query(), string(body), req.Header.Get("Authorization")})
	path := req.URL.Path
	if strings.HasPrefix(path, "/v1/owners/") {
		return response(200, "application/json", `{"id":"tea-a"}`), nil
	}
	if strings.Contains(path, "sbx-other") && req.URL.Query().Get("ownerId") != "tea-b" {
		return response(404, "application/json", `{"message":"SENSITIVE_API_ERROR"}`), nil
	}
	if path == "/v1/sandboxes" {
		if req.Method == http.MethodPost {
			return response(201, "application/json", `{"id":"sbx-a","status":"creating"}`), nil
		}
		if req.URL.Query().Get("cursor") == "page2" {
			return response(200, "application/json", "[]"), nil
		}
		return response(200, "application/json", `[{"sandbox":{"id":"sbx-a","status":"running"},"cursor":"page2"}]`), nil
	}
	if strings.HasSuffix(path, "/token") {
		op := "runs/stream"
		method := "POST"
		if strings.Contains(path, "/files/download/") {
			op = "files/download"
			method = "GET"
		}
		if strings.Contains(path, "/files/upload/") {
			op = "files/upload"
			method = "PUT"
		}
		uri := "https://sbx-a.oregon.sandbox.onrender.com/" + op
		if p := req.URL.Query().Get("path"); p != "" {
			uri += "?" + url.Values{"path": {p}}.Encode()
		}
		if f.tokenURI != "" {
			uri = f.tokenURI
		}
		b, _ := json.Marshal(sbx.SandboxConnectResponse{ExecutionId: "exe-test", Token: "SCOPED_SECRET", Method: method, Uri: uri, ExpiresAt: time.Now().Add(time.Minute)})
		return response(201, "application/json", string(b)), nil
	}
	if strings.HasSuffix(path, "/status") {
		if f.statusCode != 200 {
			return response(f.statusCode, "application/json", `{"message":"SENSITIVE_STATUS_ERROR"}`), nil
		}
		var in sbx.SandboxExecUpdateRequest
		_ = json.Unmarshal(body, &in)
		b, _ := json.Marshal(sbx.SandboxExecUpdateResponse{ExecId: "exe-test", SandboxId: "sbx-a", ExitCode: in.ExitCode})
		return response(200, "application/json", string(b)), nil
	}
	if strings.HasSuffix(path, "/terminate") {
		return response(204, "application/json", ""), nil
	}
	status := "running"
	if f.initialState != "" {
		status = f.initialState
	}
	for _, call := range f.calls {
		if strings.HasSuffix(call.Path, "/terminate") {
			status = f.terminationState
		}
	}
	return response(200, "application/json", `{"id":"sbx-a","status":"`+status+`"}`), nil
}

func (f *fixture) proxy(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proxyCalls++
	if req.Header.Get("Authorization") != "Bearer SCOPED_SECRET" {
		return nil, errors.New("unexpected auth")
	}
	if req.Header.Get(client.APIAuthHeader) != "" {
		return nil, errors.New("account auth leaked")
	}
	if strings.HasPrefix(req.URL.Path, "/runs/") {
		return response(f.proxyStatus, "text/event-stream", f.stream), nil
	}
	if req.Method == "PUT" {
		return response(204, "application/octet-stream", ""), nil
	}
	return response(f.proxyStatus, f.fileType, f.fileBody), nil
}

func testContext() context.Context {
	return session.ContextWithWorkspace(authn.ContextWithAPIToken(context.Background(), "ACCOUNT_SECRET"), "tea-a")
}

func call(t *testing.T, r *Repo, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}}
	for _, tool := range definitions(r) {
		if tool.Tool.Name == name {
			out, err := tool.Handler(testContext(), req)
			require.NoError(t, err)
			return out
		}
	}
	t.Fatalf("missing tool %s", name)
	return nil
}
func text(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	require.NotEmpty(t, result.Content)
	return result.Content[0].(mcp.TextContent).Text
}

func TestCreateReturnsBeforeReadinessAndUsesCurrentPolicy(t *testing.T) {
	r, f := newFixture(t)
	result := call(t, r, "create_sandbox", map[string]any{"network_policy": "allow-list", "allowed_domains": []any{"example.com", "*.example.org"}})
	require.False(t, result.IsError, text(t, result))
	require.Contains(t, text(t, result), `"status":"creating"`)
	require.Len(t, f.calls, 1)
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(f.calls[0].Body), &body))
	require.Equal(t, "tea-a", body["ownerId"])
	require.EqualValues(t, 600, body["timeoutSeconds"])
	network := body["networkPolicy"].(map[string]any)
	require.Equal(t, "allow-list", network["type"])
	require.NotContains(t, network, "default")
	rules := network["rules"].([]any)
	require.Equal(t, "https", rules[0].(map[string]any)["protocol"])
	require.Equal(t, "Bearer ACCOUNT_SECRET", f.calls[0].Auth)
}

func TestListAndExactIDGet(t *testing.T) {
	r, f := newFixture(t)
	list, err := r.List(testContext(), client.ListSandboxesParams{Limit: new(1)})
	require.NoError(t, err)
	require.Equal(t, "page2", *list.NextCursor)
	require.Len(t, list.Sandboxes, 1)
	next, err := r.List(testContext(), client.ListSandboxesParams{Cursor: list.NextCursor, Limit: new(1)})
	require.NoError(t, err)
	require.Empty(t, next.Sandboxes)
	require.Nil(t, next.NextCursor)
	require.NotContains(t, f.calls[0].Query, "status")
	_, err = r.Get(testContext(), "sbx-a")
	require.NoError(t, err)
	require.Equal(t, "/v1/sandboxes/sbx-a", f.calls[2].Path)
	for _, c := range f.calls {
		require.Equal(t, "tea-a", c.Owner)
	}
}

func TestExecPreservesExitAndReportsStatus(t *testing.T) {
	for _, exit := range []int{0, 7} {
		t.Run(string(rune('0'+exit)), func(t *testing.T) {
			r, f := newFixture(t)
			f.stream = ": keepalive\r\n\r\nevent: output\r\ndata: {\"stream\":\"stdout\",\r\ndata: \"data\":\"ok\\n\"}\r\n\r\nevent: output\ndata: {\"stream\":\"stderr\",\"data\":\"warning\"}\n\nevent: exit\ndata: {\"exit_code\":" + string(rune('0'+exit)) + "}\n\n"
			result, err := r.Exec(testContext(), "sbx-a", "printf ok", time.Second)
			require.NoError(t, err)
			require.Equal(t, "exited", result.Outcome)
			require.Equal(t, exit, *result.ExitCode)
			require.Equal(t, "ok\n", result.Stdout)
			require.Equal(t, "warning", result.Stderr)
			require.False(t, result.MayStillBeRunning)
			require.True(t, result.StatusPersisted)
			require.Equal(t, "exe-test", result.ExecutionID)
			require.Equal(t, 1, f.proxyCalls)
			require.Equal(t, "/v1/sandboxes/sbx-a/execs/exe-test/status", f.calls[2].Path)
			for _, c := range f.calls {
				require.Equal(t, "tea-a", c.Owner)
			}
		})
	}
}

func TestExecStatusFailureKeepsObservedResult(t *testing.T) {
	r, f := newFixture(t)
	f.statusCode = 503
	result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
	require.NoError(t, err)
	require.Equal(t, "exited", result.Outcome)
	require.Equal(t, 0, *result.ExitCode)
	require.False(t, result.StatusPersisted)
	require.Contains(t, result.Issue, "recording")
	require.NotContains(t, result.Issue, "SENSITIVE")
}

func TestExecUnknownNeverReportsCompletionOrRetries(t *testing.T) {
	for name, stream := range map[string]string{
		"eof":                 "event: output\ndata: {\"stream\":\"stdout\",\"data\":\"partial\"}\n\n",
		"missing code":        "event: exit\ndata: {}\n\n",
		"malformed":           "event: output\ndata: SECRET_BAD_JSON\n\n",
		"error event":         "event: error\ndata: {\"message\":\"SENSITIVE_GUEST_OUTPUT\"}\n\n",
		"unknown event":       "event: other\ndata: {}\n\n",
		"oversized line":      "event: output\ndata: " + strings.Repeat("x", maxEventBytes+1) + "\n\n",
		"oversized multiline": "event: output\n" + strings.Repeat("data: "+strings.Repeat("x", 4096)+"\n", 20) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			r, f := newFixture(t)
			f.stream = stream
			result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
			require.NoError(t, err)
			require.Equal(t, "unknown", result.Outcome)
			require.Nil(t, result.ExitCode)
			require.Equal(t, "exe-test", result.ExecutionID)
			require.True(t, result.MayStillBeRunning)
			require.Equal(t, 1, f.proxyCalls)
			require.Len(t, f.calls, 2)
			require.NotContains(t, result.Issue, "SENSITIVE")
			require.NotContains(t, result.Issue, "SECRET")
		})
	}
}

func TestExecDeadlineRetainsPartialOutput(t *testing.T) {
	r, f := newFixture(t)
	r.proxy.Transport = doer(func(req *http.Request) (*http.Response, error) {
		reader, writer := io.Pipe()
		go func() {
			_, _ = io.WriteString(writer, "event: output\ndata: {\"stream\":\"stdout\",\"data\":\"partial\"}\n\n")
			<-req.Context().Done()
			_ = writer.CloseWithError(req.Context().Err())
		}()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: reader}, nil
	})
	result, err := r.Exec(testContext(), "sbx-a", "sleep 9", 20*time.Millisecond)
	require.NoError(t, err)
	require.Equal(t, "partial", result.Stdout)
	require.Contains(t, result.Issue, "wait deadline")
	require.Nil(t, result.ExitCode)
	require.True(t, result.MayStillBeRunning)
	require.Equal(t, "exe-test", result.ExecutionID)
	require.Len(t, f.calls, 2)
}

func TestExecCanceledAfterTerminalEventStillPersistsStatus(t *testing.T) {
	r, f := newFixture(t)
	ctx, cancel := context.WithCancel(testContext())
	defer cancel()
	r.proxy.Transport = doer(func(req *http.Request) (*http.Response, error) {
		resp := response(200, "text/event-stream", "event: exit\ndata: {\"exit_code\":0}\n\n")
		resp.Body = &cancelOnEOF{Reader: resp.Body, cancel: cancel}
		return resp, nil
	})
	// Cancel immediately after the complete frame is read, before the status call.
	result, err := r.Exec(ctx, "sbx-a", "true", time.Second)
	require.NoError(t, err)
	require.True(t, result.StatusPersisted)
	require.Len(t, f.calls, 3)
}

type cancelOnEOF struct {
	io.Reader
	cancel context.CancelFunc
}

func (r *cancelOnEOF) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.cancel()
	}
	return n, err
}
func (r *cancelOnEOF) Close() error { return nil }

func TestOutputBoundsContinueToExit(t *testing.T) {
	r, f := newFixture(t)
	chunk, _ := json.Marshal(map[string]string{"stream": "stdout", "data": strings.Repeat("é", 4096)})
	f.stream = strings.Repeat("event: output\ndata: "+string(chunk)+"\n\n", 30) + "event: exit\ndata: {\"exit_code\":0}\n\n"
	result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
	require.NoError(t, err)
	require.Equal(t, "exited", result.Outcome)
	require.True(t, result.OutputTruncated)
	require.LessOrEqual(t, len(result.Stdout)+len(result.Stderr), maxOutputBytes)
	require.JSONEq(t, `{"exitCode":0}`, f.calls[len(f.calls)-1].Body)
}

func TestProxyEndpointValidationAndNoCredentialRedirects(t *testing.T) {
	for _, uri := range []string{
		"http://sbx-a.oregon.sandbox.onrender.com/runs/stream",
		"https://sbx-a.oregon.sandbox.onrender.com.attacker.test/runs/stream",
		"https://sbx-b.oregon.sandbox.onrender.com/runs/stream",
		"https://user:pass@sbx-a.oregon.sandbox.onrender.com/runs/stream",
		"https://sbx-a.oregon.sandbox.onrender.com/runs/stream?token=bad",
		"https://sbx-a.oregon.sandbox.onrender.com/runs/stream#fragment",
		"https://sbx-a.oregon.sandbox.onrender.com:444/runs/stream",
	} {
		t.Run(uri, func(t *testing.T) {
			r, f := newFixture(t)
			f.tokenURI = uri
			result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
			require.Error(t, err)
			require.Equal(t, "exe-test", result.ExecutionID)
			require.Zero(t, f.proxyCalls)
			require.NotContains(t, err.Error(), uri)
		})
	}
	r, f := newFixture(t)
	r.proxy.Transport = doer(func(req *http.Request) (*http.Response, error) {
		f.proxyCalls++
		resp := response(307, "text/plain", "SENSITIVE")
		resp.Header.Set("Location", "https://attacker.test")
		return resp, nil
	})
	result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
	require.NoError(t, err)
	require.Equal(t, 1, f.proxyCalls)
	require.Contains(t, result.Issue, "307")
	require.Equal(t, "unknown", result.Outcome)
}

func TestFileLimitsAndLiteralPaths(t *testing.T) {
	r, f := newFixture(t)
	p := "/tmp/quote ' $(echo forbidden).txt"
	written, err := r.File(testContext(), "sbx-a", p, new("hello"))
	require.NoError(t, err)
	require.Equal(t, "written", written.Outcome)
	require.Equal(t, p, f.calls[0].Query.Get("path"))
	require.Equal(t, "tea-a", f.calls[0].Owner)
	f.fileBody = strings.Repeat("é", maxFileBytes)
	read, err := r.File(testContext(), "sbx-a", p, nil)
	require.NoError(t, err)
	require.True(t, read.Truncated)
	require.Equal(t, maxFileBytes, len(read.Content))
	require.Equal(t, "exe-test", read.ExecutionID)
	f.fileType = "application/x-tar"
	_, err = r.File(testContext(), "sbx-a", "/tmp", nil)
	require.ErrorContains(t, err, "directory")
	f.fileType = "application/octet-stream"
	f.fileBody = "binary\x00value"
	_, err = r.File(testContext(), "sbx-a", "/tmp/binary", nil)
	require.ErrorContains(t, err, "not UTF-8 text")
}

func TestTerminateRequiresObservedTerminalState(t *testing.T) {
	for _, state := range []string{"terminated", "running", "errored"} {
		t.Run(state, func(t *testing.T) {
			r, f := newFixture(t)
			f.terminationState = state
			result, err := r.Terminate(testContext(), "sbx-a")
			require.NoError(t, err)
			require.True(t, result.RequestAccepted)
			require.Equal(t, state, string(result.ObservedStatus))
			require.Equal(t, state == "terminated", result.VerifiedTerminated)
			require.Len(t, f.calls, 2)
			for _, c := range f.calls {
				require.Equal(t, "tea-a", c.Owner)
			}
		})
	}
}

func TestCrossWorkspaceOperationsFailBeforeProxy(t *testing.T) {
	r, f := newFixture(t)
	_, err := r.Get(testContext(), "sbx-other")
	require.Error(t, err)
	_, err = r.Exec(testContext(), "sbx-other", "true", time.Second)
	require.Error(t, err)
	_, err = r.File(testContext(), "sbx-other", "/tmp/a", nil)
	require.Error(t, err)
	_, err = r.File(testContext(), "sbx-other", "/tmp/a", new("data"))
	require.Error(t, err)
	result, err := r.Terminate(testContext(), "sbx-other")
	require.NoError(t, err)
	require.False(t, result.VerifiedTerminated)
	require.Zero(t, f.proxyCalls)
	for _, c := range f.calls {
		require.Equal(t, "tea-a", c.Owner)
	}
}

func TestConcurrentCallsKeepTheirWorkspace(t *testing.T) {
	r, f := newFixture(t)
	var wg sync.WaitGroup
	for _, workspace := range []string{"tea-a", "tea-b"} {
		wg.Go(func() {
			ctx := session.ContextWithWorkspace(testContext(), workspace)
			for range 5 {
				_, err := r.List(ctx, client.ListSandboxesParams{Cursor: &workspace})
				require.NoError(t, err)
			}
		})
	}
	wg.Wait()
	for _, c := range f.calls {
		require.Equal(t, c.Query.Get("cursor"), c.Owner)
	}
}

func TestDecodeBoundsAndRedactsErrors(t *testing.T) {
	_, err := decode[map[string]any](response(500, "application/json", `{"message":"SECRET"}`), nil, 200)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SECRET")
	_, err = decode[map[string]any](response(200, "application/json", strings.Repeat(" ", maxResponseBytes+1)), nil, 200)
	require.ErrorContains(t, err, "size")
	_, err = decode[map[string]any](nil, errors.New("https://SECRET"), 200)
	require.NotContains(t, err.Error(), "SECRET")
	_, err = decode[map[string]any](response(200, "application/json", `{"x":"SECRET"`), nil, 200)
	require.NotContains(t, err.Error(), "SECRET")
}

func TestLargeStreamStopsWithUnknownOutcome(t *testing.T) {
	out := &ExecResult{}
	// An unbounded producer cannot keep this parser consuming indefinitely.
	reader := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte(": ping\n"), maxStreamBytes/7+2)), strings.NewReader("event: exit\ndata: {\"exit_code\":0}\n\n"))
	err := collectOutput(reader, out)
	require.ErrorContains(t, err, "read limit")
	require.Nil(t, out.ExitCode)
}

func TestConnectHandlesSuspensionButRejectsTerminalState(t *testing.T) {
	for _, state := range []string{"running", "suspended", "resuming", "suspending", "creating", "terminated", "errored"} {
		t.Run(state, func(t *testing.T) {
			r, f := newFixture(t)
			f.initialState = state
			result, err := r.Exec(testContext(), "sbx-a", "true", time.Second)
			if state == "terminated" || state == "errored" {
				require.Error(t, err)
				require.Zero(t, f.proxyCalls)
				require.Equal(t, "not_started", result.Outcome)
			} else {
				require.NoError(t, err)
				require.Equal(t, "exited", result.Outcome)
			}
		})
	}
}

func TestReportContextPreservesDeadlineAndWorkspaceAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(testContext(), 100*time.Millisecond)
	deadline, _ := ctx.Deadline()
	cancel()
	report, done := reportContext(ctx)
	defer done()
	got, _ := report.Deadline()
	require.Equal(t, deadline, got)
	require.NoError(t, report.Err())
	workspace, err := owner(report)
	require.NoError(t, err)
	require.Equal(t, "tea-a", workspace)
}

func TestFileTransportFailureIsAmbiguousAndNeverRetried(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "write"}[write], func(t *testing.T) {
			r, f := newFixture(t)
			attempts := 0
			r.proxy.Transport = doer(func(req *http.Request) (*http.Response, error) {
				attempts++
				return nil, errors.New("SENSITIVE_TRANSPORT_ERROR")
			})
			var content *string
			if write {
				content = new("data")
			}
			out, err := r.File(testContext(), "sbx-a", "/tmp/file", content)
			require.NoError(t, err)
			require.Equal(t, "unknown", out.Outcome)
			require.Equal(t, "exe-test", out.ExecutionID)
			require.Equal(t, "sbx-a", out.SandboxID)
			require.NotContains(t, out.Issue, "SENSITIVE")
			require.Equal(t, 1, attempts)
			require.Len(t, f.calls, 1)
		})
	}
}

func TestFileTruncationPreservesUTF8Boundary(t *testing.T) {
	r, f := newFixture(t)
	f.fileBody = strings.Repeat("x", maxFileBytes-1) + "é"
	out, err := r.File(testContext(), "sbx-a", "/tmp/file", nil)
	require.NoError(t, err)
	require.True(t, out.Truncated)
	require.Equal(t, maxFileBytes-1, out.Bytes)
	require.Equal(t, strings.Repeat("x", maxFileBytes-1), out.Content)

	f.fileBody = "invalid\xffutf8"
	out, err = r.File(testContext(), "sbx-a", "/tmp/file", nil)
	require.ErrorContains(t, err, "not UTF-8 text")
	require.Equal(t, "exe-test", out.ExecutionID)
	require.Empty(t, out.Content)
}

func TestSetupDeadlineDoesNotSubmitCommand(t *testing.T) {
	requests := 0
	c, err := client.NewClientWithResponses("https://api.example.test/v1", client.WithHTTPClient(doer(func(req *http.Request) (*http.Response, error) {
		requests++
		<-req.Context().Done()
		return nil, req.Context().Err()
	})))
	require.NoError(t, err)
	r := NewRepo(c)
	r.proxy.Transport = doer(func(*http.Request) (*http.Response, error) {
		t.Error("command was submitted after setup failed")
		return nil, errors.New("unexpected proxy request")
	})
	ctx, cancel := context.WithTimeout(testContext(), 20*time.Millisecond)
	defer cancel()
	out, err := r.Exec(ctx, "sbx-a", "true", time.Second)
	require.Error(t, err)
	require.Equal(t, "not_started", out.Outcome)
	require.False(t, out.MayStillBeRunning)
	require.Empty(t, out.ExecutionID)
	require.Equal(t, 1, requests)
}
