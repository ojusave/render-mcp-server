package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
)

// A connect URI comes only from the authenticated Render API. Validate its
// sandbox identity, operation, TLS origin and file path before sending the
// short-lived credential. No account/OAuth headers are forwarded to the VM.
func proxyRequest(ctx context.Context, conn *sbx.SandboxConnectResponse, id, operation, filePath string, body io.Reader) (*http.Request, error) {
	u, err := url.Parse(conn.Uri)
	if err != nil || u == nil {
		return nil, errors.New("invalid Sandbox connection endpoint")
	}
	wantMethod := http.MethodPost
	if operation == "files/upload" {
		wantMethod = http.MethodPut
	}
	if operation == "files/download" {
		wantMethod = http.MethodGet
	}
	host := u.Hostname()
	suffixOK := strings.HasSuffix(host, ".sandbox.onrender.com") || strings.HasSuffix(host, ".sandbox.onrender-staging.com")
	parts := strings.Split(host, ".")
	if u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") ||
		!suffixOK || len(parts) != 5 || parts[0] != id || parts[1] == "" ||
		u.EscapedPath() != "/"+operation || conn.Method != wantMethod ||
		conn.Token == "" || conn.ExecutionId == "" {
		return nil, errors.New("invalid Sandbox connection endpoint")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid Sandbox connection query")
	}
	if filePath == "" {
		if len(query) != 0 {
			return nil, errors.New("unexpected Sandbox connection query")
		}
	} else if len(query) != 1 || len(query["path"]) != 1 || query.Get("path") != filePath {
		return nil, errors.New("Sandbox connection path does not match requested file")
	}
	req, err := http.NewRequestWithContext(ctx, wantMethod, conn.Uri, body)
	if err != nil {
		return nil, errors.New("invalid Sandbox connection request")
	}
	req.Header.Set("Authorization", "Bearer "+conn.Token)
	req.Header.Set("Accept-Encoding", "identity")
	return req, nil
}

func checkProxyResponse(resp *http.Response, err error) error {
	if err != nil {
		return errors.New("Sandbox connection interrupted; operation outcome may be unknown")
	}
	if resp == nil {
		return errors.New("Sandbox response unavailable")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Sandbox proxy returned HTTP %d", resp.StatusCode)
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return errors.New("unsupported Sandbox response encoding")
	}
	return nil
}

type FileResult struct {
	SandboxID   string `json:"sandbox_id"`
	ExecutionID string `json:"execution_id,omitempty"`
	Path        string `json:"path"`
	Outcome     string `json:"outcome"`
	Content     string `json:"content,omitempty"`
	Bytes       int    `json:"bytes"`
	Truncated   bool   `json:"truncated"`
	Issue       string `json:"issue,omitempty"`
}

func (r *Repo) File(ctx context.Context, id, path string, content *string) (*FileResult, error) {
	out := &FileResult{SandboxID: id, Path: path, Outcome: "not_started"}
	workspace, err := owner(ctx)
	if err != nil {
		return out, err
	}
	op := "download"
	if content != nil {
		op = "upload"
	}
	resp, err := r.client.ConnectSandboxFiles(ctx, id, op, &client.ConnectSandboxFilesParams{OwnerId: &workspace, Path: path})
	conn, err := decode[sbx.SandboxConnectResponse](resp, err, http.StatusCreated)
	if err != nil {
		return out, err
	}
	out.ExecutionID = conn.ExecutionId
	var body io.Reader
	if content != nil {
		body = strings.NewReader(*content)
	}
	req, err := proxyRequest(ctx, conn, id, "files/"+op, path, body)
	if err != nil {
		return out, err
	}
	if content != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	out.Outcome = "unknown"
	resp, err = r.proxy.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err = checkProxyResponse(resp, err); err != nil {
		out.Outcome = "unknown"
		out.Issue = err.Error()
		return out, nil
	}
	if content != nil {
		out.Outcome = "written"
		out.Bytes = len(*content)
		return out, nil
	}
	kind, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || kind != "application/octet-stream" {
		return out, errors.New("only single text files are supported; directory archives are not returned")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFileBytes+1))
	if err != nil {
		out.Outcome = "unknown"
		out.Issue = "file response interrupted"
		return out, nil
	}
	out.Truncated = len(data) > maxFileBytes
	if out.Truncated {
		data = data[:maxFileBytes]
	}
	// At a truncation boundary, omit an incomplete UTF-8 rune rather than
	// manufacture replacement characters. Internal invalid UTF-8 remains an error.
	if out.Truncated {
		data = trimIncompleteRune(data)
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return out, errors.New("file is not UTF-8 text; use the CLI or SDK for binary files")
	}
	out.Outcome = "read"
	out.Content = string(data)
	out.Bytes = len(data)
	return out, nil
}

func trimIncompleteRune(data []byte) []byte {
	start := len(data) - 1
	for start >= 0 && !utf8.RuneStart(data[start]) {
		start--
	}
	if start >= 0 && !utf8.FullRune(data[start:]) {
		return data[:start]
	}
	return data
}
