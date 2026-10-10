package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/session"
)

// Use the generated request builders and the existing authenticated client,
// but decode bounded bodies here. Raw API errors can contain input or secrets.
type sandboxClient interface {
	CreateSandbox(context.Context, client.CreateSandboxJSONRequestBody, ...client.RequestEditorFn) (*http.Response, error)
	RetrieveSandbox(context.Context, string, *client.RetrieveSandboxParams, ...client.RequestEditorFn) (*http.Response, error)
	ListSandboxes(context.Context, *client.ListSandboxesParams, ...client.RequestEditorFn) (*http.Response, error)
	TerminateSandbox(context.Context, string, *client.TerminateSandboxParams, ...client.RequestEditorFn) (*http.Response, error)
	ConnectSandboxRun(context.Context, string, string, *client.ConnectSandboxRunParams, client.ConnectSandboxRunJSONRequestBody, ...client.RequestEditorFn) (*http.Response, error)
	ConnectSandboxFiles(context.Context, string, string, *client.ConnectSandboxFilesParams, ...client.RequestEditorFn) (*http.Response, error)
	UpdateSandboxExec(context.Context, string, string, *client.UpdateSandboxExecParams, client.UpdateSandboxExecJSONRequestBody, ...client.RequestEditorFn) (*http.Response, error)
}

const (
	handlerTimeout   = 45 * time.Second
	setupTimeout     = 10 * time.Second
	statusTimeout    = 3 * time.Second
	maxWait          = 30 * time.Second
	maxResponseBytes = 1 << 20
	maxOutputBytes   = 64 << 10
	maxFileBytes     = 64 << 10
	maxCommandBytes  = 16 << 10
	maxEventBytes    = 64 << 10
	maxStreamBytes   = 4 << 20
)

type Repo struct {
	client sandboxClient
	proxy  *http.Client
}

func NewRepo(c sandboxClient) *Repo {
	return &Repo{
		client: c,
		proxy: &http.Client{
			Timeout: maxWait,
			// Never forward a scoped credential to a redirect destination.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func owner(ctx context.Context) (string, error) {
	id, err := session.FromContext(ctx).GetWorkspace(ctx)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("select a workspace before using Sandbox tools")
	}
	return id, nil
}

func decode[T any](resp *http.Response, err error, want int) (*T, error) {
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, errors.New("Render API request failed; response unavailable")
	}
	if resp == nil || resp.Body == nil {
		return nil, errors.New("Render API response unavailable")
	}
	if resp.StatusCode != want {
		// Do not pass raw bodies or transport errors to the tool error logger.
		return nil, fmt.Errorf("Render API returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, errors.New("Render API response interrupted")
	}
	if len(b) > maxResponseBytes {
		return nil, errors.New("Render API response exceeds the size limit")
	}
	var value T
	if err := json.Unmarshal(b, &value); err != nil {
		return nil, errors.New("Render API returned invalid JSON")
	}
	return &value, nil
}

func (r *Repo) Create(ctx context.Context, input client.CreateSandboxJSONRequestBody) (*sbx.Sandbox, error) {
	id, err := owner(ctx)
	if err != nil {
		return nil, err
	}
	input.OwnerId = id
	resp, err := r.client.CreateSandbox(ctx, input)
	value, err := decode[sbx.Sandbox](resp, err, http.StatusCreated)
	if err != nil {
		return nil, fmt.Errorf("%w; creation outcome may be unknown, list sandboxes before retrying", err)
	}
	if value.Id == "" {
		return nil, errors.New("creation returned no sandbox ID; list sandboxes before retrying")
	}
	// Creation is asynchronous. Preserve the ID immediately without waiting or
	// implicitly terminating a persistent sandbox on a readiness timeout.
	return value, nil
}

func (r *Repo) Get(ctx context.Context, id string) (*sbx.Sandbox, error) {
	workspace, err := owner(ctx)
	if err != nil {
		return nil, err
	}
	return r.get(ctx, workspace, id)
}

func (r *Repo) get(ctx context.Context, workspace, id string) (*sbx.Sandbox, error) {
	// The backend currently enforces ownerId for exact-ID operations, despite
	// stale schema comments saying it is ignored. Never omit this parameter.
	resp, err := r.client.RetrieveSandbox(ctx, id, &client.RetrieveSandboxParams{OwnerId: &workspace})
	value, err := decode[sbx.Sandbox](resp, err, http.StatusOK)
	if err == nil && value.Id != id {
		return nil, errors.New("Render API returned an unexpected sandbox ID")
	}
	return value, err
}

type ListResult struct {
	Sandboxes  []sbx.Sandbox `json:"sandboxes"`
	NextCursor *string       `json:"next_cursor"`
}

func (r *Repo) List(ctx context.Context, params client.ListSandboxesParams) (*ListResult, error) {
	workspace, err := owner(ctx)
	if err != nil {
		return nil, err
	}
	params.OwnerId = workspace
	resp, err := r.client.ListSandboxes(ctx, &params)
	page, err := decode[[]client.SandboxWithCursor](resp, err, http.StatusOK)
	if err != nil {
		return nil, err
	}
	out := &ListResult{Sandboxes: make([]sbx.Sandbox, 0, len(*page))}
	for _, row := range *page {
		out.Sandboxes = append(out.Sandboxes, row.Sandbox)
	}
	if len(*page) > 0 {
		out.NextCursor = &(*page)[len(*page)-1].Cursor
	}
	return out, nil
}

type TerminateResult struct {
	SandboxID          string            `json:"sandbox_id"`
	RequestAccepted    bool              `json:"request_accepted"`
	VerifiedTerminated bool              `json:"verified_terminated"`
	ObservedStatus     sbx.SandboxStatus `json:"observed_status,omitempty"`
	Issue              string            `json:"issue,omitempty"`
}

func (r *Repo) Terminate(ctx context.Context, id string) (*TerminateResult, error) {
	out := &TerminateResult{SandboxID: id}
	workspace, err := owner(ctx)
	if err != nil {
		return out, err
	}
	resp, err := r.client.TerminateSandbox(ctx, id, &client.TerminateSandboxParams{OwnerId: &workspace})
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil || resp == nil {
		out.Issue = "termination response unavailable; verify this sandbox before retrying"
		return out, nil
	}
	if resp.StatusCode != http.StatusNoContent {
		out.Issue = fmt.Sprintf("termination returned HTTP %d; terminal state not verified", resp.StatusCode)
		return out, nil
	}
	out.RequestAccepted = true
	// Verification is independent of caller cancellation, with a small budget.
	// It reports backend state, not physical VM deletion.
	verifyCtx, cancel := reportContext(ctx)
	defer cancel()
	value, err := r.get(verifyCtx, workspace, id)
	if err != nil {
		out.Issue = "termination accepted; final state could not be verified"
		return out, nil
	}
	out.ObservedStatus = value.Status
	out.VerifiedTerminated = value.Status == sbx.SandboxStatusTerminated
	if !out.VerifiedTerminated {
		out.Issue = "termination accepted; sandbox is not yet observed terminated"
	}
	return out, nil
}

// Ignore caller cancellation for bounded completion/cleanup verification, but
// never extend the original handler deadline.
func reportContext(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(statusTimeout)
	if original, ok := ctx.Deadline(); ok && original.Before(deadline) {
		deadline = original
	}
	return context.WithDeadline(context.WithoutCancel(ctx), deadline)
}
