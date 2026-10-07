package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/session"
)

//go:generate go tool counterfeiter -o ../fakes/fakesandboxrepoclient_gen.go . sandboxRepoClient
type sandboxRepoClient interface {
	CreateSandboxWithResponse(ctx context.Context, body client.CreateSandboxJSONRequestBody, reqEditors ...client.RequestEditorFn) (*client.CreateSandboxResponse, error)
	RetrieveSandboxWithResponse(ctx context.Context, sandboxId sbx.SandboxId, params *client.RetrieveSandboxParams, reqEditors ...client.RequestEditorFn) (*client.RetrieveSandboxResponse, error)
	ListSandboxesWithResponse(ctx context.Context, params *client.ListSandboxesParams, reqEditors ...client.RequestEditorFn) (*client.ListSandboxesResponse, error)
	TerminateSandboxWithResponse(ctx context.Context, sandboxId sbx.SandboxId, params *client.TerminateSandboxParams, reqEditors ...client.RequestEditorFn) (*client.TerminateSandboxResponse, error)
	ConnectSandboxRunWithResponse(ctx context.Context, sandboxId sbx.SandboxId, operation string, params *client.ConnectSandboxRunParams, body client.ConnectSandboxRunJSONRequestBody, reqEditors ...client.RequestEditorFn) (*client.ConnectSandboxRunResponse, error)
	ConnectSandboxFilesWithResponse(ctx context.Context, sandboxId sbx.SandboxId, operation string, params *client.ConnectSandboxFilesParams, reqEditors ...client.RequestEditorFn) (*client.ConnectSandboxFilesResponse, error)
	ListSandboxFilesWithResponse(ctx context.Context, sandboxId sbx.SandboxId, params *client.ListSandboxFilesParams, reqEditors ...client.RequestEditorFn) (*client.ListSandboxFilesResponse, error)
	CreateSandboxSnapshotWithResponse(ctx context.Context, sandboxId sbx.SandboxId, params *client.CreateSandboxSnapshotParams, body client.CreateSandboxSnapshotJSONRequestBody, reqEditors ...client.RequestEditorFn) (*client.CreateSandboxSnapshotResponse, error)
	RetrieveSandboxSnapshotWithResponse(ctx context.Context, sandboxGroupId sbx.SandboxGroupId, snapshotId sbx.SnapshotId, params *client.RetrieveSandboxSnapshotParams, reqEditors ...client.RequestEditorFn) (*client.RetrieveSandboxSnapshotResponse, error)
	ListSandboxSnapshotsWithResponse(ctx context.Context, sandboxGroupId sbx.SandboxGroupId, params *client.ListSandboxSnapshotsParams, reqEditors ...client.RequestEditorFn) (*client.ListSandboxSnapshotsResponse, error)
	ListSandboxGroupsWithResponse(ctx context.Context, params *client.ListSandboxGroupsParams, reqEditors ...client.RequestEditorFn) (*client.ListSandboxGroupsResponse, error)
}

// Repo wraps the sandbox API. Every call is scoped to the session's workspace,
// so the API itself refuses sandboxes that belong to another workspace.
type Repo struct {
	client     sandboxRepoClient
	proxy      *http.Client // talks to the sandbox host with short-lived connect tokens
	pollEvery  time.Duration
	readyAfter time.Duration
}

func NewRepo(c sandboxRepoClient) *Repo {
	return &Repo{
		client:     c,
		proxy:      &http.Client{Transport: http.DefaultTransport},
		pollEvery:  time.Second,
		readyAfter: 90 * time.Second,
	}
}

func workspace(ctx context.Context) (string, error) {
	return session.FromContext(ctx).GetWorkspace(ctx)
}

type CreateInput struct {
	TimeoutSeconds int
	Network        sbx.SandboxNetworkPolicyDefault
	AllowedDomains []string
	Snapshot       string
	Env            map[string]string
}

func (r *Repo) Create(ctx context.Context, in CreateInput) (*sbx.Sandbox, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	body := client.CreateSandboxJSONRequestBody{OwnerId: owner}
	if in.TimeoutSeconds > 0 {
		body.TimeoutSeconds = &in.TimeoutSeconds
	}
	if in.Network != "" {
		policy := sbx.SandboxNetworkPolicy{Default: in.Network}
		if in.Network == sbx.AllowList {
			domains := in.AllowedDomains
			policy.AllowedDomains = &domains
		}
		body.NetworkPolicy = &policy
	}
	if len(in.Env) > 0 {
		env := in.Env
		body.Env = &env
	}
	if in.Snapshot != "" {
		if strings.HasPrefix(in.Snapshot, "snp-") {
			id := in.Snapshot
			body.SnapshotId = &id
		} else {
			name := in.Snapshot
			body.SnapshotName = &name
		}
	}
	resp, err := r.client.CreateSandboxWithResponse(ctx, body)
	if err != nil {
		return nil, err
	}
	created, err := client.BodyFromResponse(resp.JSON201, resp)
	if err != nil {
		return nil, err
	}
	ready, err := r.waitRunning(ctx, owner, created.Id)
	if err != nil {
		_ = r.Terminate(ctx, created.Id)
		return nil, err
	}
	return ready, nil
}

func (r *Repo) waitRunning(ctx context.Context, owner, id string) (*sbx.Sandbox, error) {
	deadline := time.Now().Add(r.readyAfter)
	for {
		resp, err := r.client.RetrieveSandboxWithResponse(ctx, id, &client.RetrieveSandboxParams{OwnerId: &owner})
		if err != nil {
			return nil, err
		}
		s, err := client.BodyFromResponse(resp.JSON200, resp)
		if err != nil {
			return nil, err
		}
		switch s.Status {
		case sbx.SandboxStatus("running"):
			return s, nil
		case sbx.SandboxStatus("errored"), sbx.SandboxStatus("terminated"):
			return nil, fmt.Errorf("sandbox %s is %s", id, s.Status)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("sandbox %s is still %s after %s", id, s.Status, r.readyAfter)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(r.pollEvery):
		}
	}
}

func (r *Repo) List(ctx context.Context, includeTerminated bool) ([]sbx.Sandbox, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	params := &client.ListSandboxesParams{OwnerId: owner}
	if !includeTerminated {
		statuses := []sbx.SandboxStatus{"creating", "running", "suspended", "resuming"}
		params.Status = &statuses
	}
	limit := client.LimitParam(50)
	params.Limit = &limit
	resp, err := r.client.ListSandboxesWithResponse(ctx, params)
	if err != nil {
		return nil, err
	}
	page, err := client.BodyFromResponse(resp.JSON200, resp)
	if err != nil {
		return nil, err
	}
	out := make([]sbx.Sandbox, 0, len(*page))
	for _, item := range *page {
		out = append(out, item.Sandbox)
	}
	return out, nil
}

func (r *Repo) Terminate(ctx context.Context, id string) error {
	owner, err := workspace(ctx)
	if err != nil {
		return err
	}
	resp, err := r.client.TerminateSandboxWithResponse(ctx, id, &client.TerminateSandboxParams{OwnerId: &owner})
	if err != nil {
		return err
	}
	if resp.StatusCode() >= 300 {
		return client.ErrorFromResponse(resp)
	}
	return nil
}

// ExecResult is what one command produced.
type ExecResult struct {
	ExitCode        *int    `json:"exitCode"`
	TimedOut        bool    `json:"timedOut"`
	DurationSeconds float64 `json:"durationSeconds"`
	Stdout          string  `json:"stdout"`
	Stderr          string  `json:"stderr"`
}

// Exec runs command through bash in the sandbox and collects its output.
// It mints a run token from the API, then streams Server-Sent Events from the
// sandbox host: "output" events carry stdout or stderr chunks, and one "exit"
// event carries the exit code.
func (r *Repo) Exec(ctx context.Context, id, command string, timeout time.Duration) (*ExecResult, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.ConnectSandboxRunWithResponse(ctx, id, "stream",
		&client.ConnectSandboxRunParams{OwnerId: &owner},
		client.ConnectSandboxRunJSONRequestBody{Command: &command})
	if err != nil {
		return nil, err
	}
	conn, err := client.BodyFromResponse(resp.JSON201, resp)
	if err != nil {
		return nil, err
	}

	payload, _ := json.Marshal(map[string]string{"command": command})
	// The sandbox enforces the command timeout; this deadline only guards a dead connection.
	streamCtx, cancel := context.WithTimeout(ctx, timeout+60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(streamCtx, conn.Method, conn.Uri, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Content-Type", "application/json")

	started := time.Now()
	httpResp, err := r.proxy.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connect to sandbox %s: %w", id, err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(httpResp.Body, 2048))
		return nil, fmt.Errorf("sandbox %s exec failed: %s: %s", id, httpResp.Status, strings.TrimSpace(string(body)))
	}

	result := &ExecResult{}
	var stdout, stderr strings.Builder
	err = readSSE(httpResp.Body, func(event, data string) (bool, error) {
		switch event {
		case "output":
			var out struct {
				Stream string `json:"stream"`
				Data   string `json:"data"`
			}
			if err := json.Unmarshal([]byte(data), &out); err != nil {
				return false, fmt.Errorf("bad output event: %w", err)
			}
			if out.Stream == "stderr" {
				stderr.WriteString(out.Data)
			} else {
				stdout.WriteString(out.Data)
			}
		case "exit":
			var exit struct {
				ExitCode int `json:"exit_code"`
			}
			if err := json.Unmarshal([]byte(data), &exit); err != nil {
				return false, fmt.Errorf("bad exit event: %w", err)
			}
			result.ExitCode = &exit.ExitCode
			return true, nil
		case "error":
			var e struct {
				Status  int    `json:"status"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal([]byte(data), &e)
			return false, fmt.Errorf("sandbox exec error %d: %s", e.Status, e.Message)
		}
		return false, nil
	})
	result.DurationSeconds = time.Since(started).Round(10 * time.Millisecond).Seconds()
	result.Stdout = truncate(stdout.String(), maxOutputChars)
	result.Stderr = truncate(stderr.String(), maxOutputChars)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	result.TimedOut = result.ExitCode == nil || *result.ExitCode == 124
	return result, nil
}

// readSSE calls handle for each event until it returns done or the stream ends.
func readSSE(r io.Reader, handle func(event, data string) (bool, error)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var event string
	var data []string
	flush := func() (bool, error) {
		if event == "" && len(data) == 0 {
			return false, nil
		}
		done, err := handle(event, strings.Join(data, "\n"))
		event, data = "", nil
		return done, err
	}
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		switch {
		case line == "":
			if done, err := flush(); done || err != nil {
				return err
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[len("event:"):])
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(line[len("data:"):], " "))
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if done, err := flush(); done || err != nil {
		return err
	}
	return errors.New("sandbox exec stream ended without an exit event")
}

func (r *Repo) fileConnection(ctx context.Context, id, operation, path string) (*sbx.SandboxConnectResponse, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.ConnectSandboxFilesWithResponse(ctx, id, operation,
		&client.ConnectSandboxFilesParams{OwnerId: &owner, Path: path})
	if err != nil {
		return nil, err
	}
	return client.BodyFromResponse(resp.JSON201, resp)
}

func (r *Repo) WriteFile(ctx context.Context, id, path string, content []byte) error {
	conn, err := r.fileConnection(ctx, id, "upload", path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, conn.Method, conn.Uri, bytes.NewReader(content))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.ContentLength = int64(len(content))
	resp, err := r.proxy.Do(req)
	if err != nil {
		return fmt.Errorf("upload to sandbox %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("upload to sandbox %s failed: %s: %s", id, resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

var ErrFileNotFound = errors.New("file not found")
var ErrIsDirectory = errors.New("path is a directory; use list_sandbox_files instead")

func (r *Repo) ReadFile(ctx context.Context, id, path string, maxBytes int64) ([]byte, int64, error) {
	conn, err := r.fileConnection(ctx, id, "download", path)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, conn.Method, conn.Uri, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	resp, err := r.proxy.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("download from sandbox %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, ErrFileNotFound
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, 0, fmt.Errorf("download from sandbox %s failed: %s: %s", id, resp.Status, strings.TrimSpace(string(body)))
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "x-tar") {
		return nil, 0, ErrIsDirectory
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, 0, err
	}
	size := resp.ContentLength
	if size < 0 {
		size = int64(len(data))
	}
	if int64(len(data)) > maxBytes {
		data = data[:maxBytes]
	}
	return data, size, nil
}

// FileEntry is one item in a directory listing.
type FileEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

// ListFiles lists a directory. It uses the files API when the server offers it,
// and falls back to running find in the sandbox, which works everywhere.
func (r *Repo) ListFiles(ctx context.Context, id, path string) (string, []FileEntry, error) {
	if path == "" {
		path = "/root"
	}
	depth := 1
	resp, err := r.client.ListSandboxFilesWithResponse(ctx, id, &client.ListSandboxFilesParams{Path: path, Depth: &depth})
	if err == nil && resp.JSON200 != nil {
		out := make([]FileEntry, 0, len(resp.JSON200.Entries))
		for _, e := range resp.JSON200.Entries {
			out = append(out, FileEntry{Name: e.Name, Type: string(e.Type), Size: int64(e.Size)})
		}
		return resp.JSON200.Path, out, nil
	}
	if err == nil && resp.StatusCode() != http.StatusNotFound {
		return "", nil, client.ErrorFromResponse(resp)
	}

	cmd := fmt.Sprintf("test -d %[1]s || { echo 'not a directory' >&2; exit 2; }; "+
		"find %[1]s -mindepth 1 -maxdepth 1 -printf '%%y\t%%s\t%%f\n' | sort -k3 | head -500", shellQuote(path))
	res, err := r.Exec(ctx, id, cmd, 30*time.Second)
	if err != nil {
		return "", nil, err
	}
	if res.ExitCode == nil || *res.ExitCode != 0 {
		return "", nil, fmt.Errorf("%s: %s", path, strings.TrimSpace(res.Stderr))
	}
	kinds := map[string]string{"d": "directory", "f": "file", "l": "symlink"}
	var out []FileEntry
	for _, line := range strings.Split(strings.TrimSpace(res.Stdout), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		var size int64
		fmt.Sscan(parts[1], &size)
		kind := kinds[parts[0]]
		if kind == "" {
			kind = "other"
		}
		out = append(out, FileEntry{Name: parts[2], Type: kind, Size: size})
	}
	return path, out, nil
}

func (r *Repo) Snapshot(ctx context.Context, id, name string) (*sbx.SandboxSnapshot, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	body := client.CreateSandboxSnapshotJSONRequestBody{}
	if name != "" {
		body.Name = &name
	}
	resp, err := r.client.CreateSandboxSnapshotWithResponse(ctx, id, &client.CreateSandboxSnapshotParams{OwnerId: &owner}, body)
	if err != nil {
		return nil, err
	}
	snap, err := client.BodyFromResponse(resp.JSON202, resp)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Minute)
	for snap.Status == sbx.SandboxSnapshotStatusCreating && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return snap, ctx.Err()
		case <-time.After(2 * r.pollEvery):
		}
		got, err := r.client.RetrieveSandboxSnapshotWithResponse(ctx, snap.SandboxGroupId, snap.Id,
			&client.RetrieveSandboxSnapshotParams{OwnerId: &owner})
		if err != nil {
			return nil, err
		}
		if snap, err = client.BodyFromResponse(got.JSON200, got); err != nil {
			return nil, err
		}
	}
	return snap, nil
}

func (r *Repo) ListSnapshots(ctx context.Context) ([]sbx.SandboxSnapshot, error) {
	owner, err := workspace(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := r.client.ListSandboxGroupsWithResponse(ctx, &client.ListSandboxGroupsParams{OwnerId: owner})
	if err != nil {
		return nil, err
	}
	page, err := client.BodyFromResponse(groups.JSON200, groups)
	if err != nil {
		return nil, err
	}
	if len(*page) == 0 {
		return nil, errors.New("Render Sandboxes are not enabled for this workspace")
	}
	statuses := []sbx.SandboxSnapshotStatus{sbx.SandboxSnapshotStatusAvailable}
	resp, err := r.client.ListSandboxSnapshotsWithResponse(ctx, (*page)[0].SandboxGroup.Id,
		&client.ListSandboxSnapshotsParams{OwnerId: owner, Status: &statuses})
	if err != nil {
		return nil, err
	}
	snaps, err := client.BodyFromResponse(resp.JSON200, resp)
	if err != nil {
		return nil, err
	}
	out := make([]sbx.SandboxSnapshot, 0, len(*snaps))
	for _, s := range *snaps {
		out = append(out, s.Snapshot)
	}
	return out, nil
}
