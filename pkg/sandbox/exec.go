package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
)

type ExecResult struct {
	SandboxID         string `json:"sandbox_id"`
	ExecutionID       string `json:"execution_id,omitempty"`
	Outcome           string `json:"execution_outcome"`
	ExitCode          *int   `json:"exit_code"`
	MayStillBeRunning bool   `json:"may_still_be_running"`
	Stdout            string `json:"stdout"`
	Stderr            string `json:"stderr"`
	OutputTruncated   bool   `json:"output_truncated"`
	StatusPersisted   bool   `json:"status_persisted"`
	Issue             string `json:"issue,omitempty"`
}

func (r *Repo) Exec(ctx context.Context, id, command string, wait time.Duration) (*ExecResult, error) {
	out := &ExecResult{SandboxID: id, Outcome: "not_started"}
	workspace, err := owner(ctx)
	if err != nil {
		return out, err
	}
	// Budget setup separately so slow readiness/token requests cannot consume
	// the entire handler deadline before a command is submitted.
	setupCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	sb, err := r.get(setupCtx, workspace, id)
	if err != nil {
		return out, err
	}
	switch sb.Status {
	case sbx.SandboxStatusRunning, sbx.SandboxStatusSuspended, sbx.SandboxStatusSuspending, sbx.SandboxStatusResuming, sbx.SandboxStatusCreating:
		// The connect endpoint admits commands only when running and resumes
		// suspended sandboxes. Its wait stays within the setup budget.
	default:
		return out, errors.New("sandbox cannot execute commands in its current state")
	}
	resp, err := r.client.ConnectSandboxRun(setupCtx, id, "stream", &client.ConnectSandboxRunParams{OwnerId: &workspace}, client.ConnectSandboxRunJSONRequestBody{Command: &command})
	conn, err := decode[sbx.SandboxConnectResponse](resp, err, http.StatusCreated)
	if err != nil {
		return out, err
	}
	out.ExecutionID = conn.ExecutionId
	payload, _ := json.Marshal(map[string]string{"command": command})
	streamCtx, stop := context.WithTimeout(ctx, wait)
	defer stop()
	req, err := proxyRequest(streamCtx, conn, id, "runs/stream", "", bytes.NewReader(payload))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	// From the first proxy request onward, failed delivery is ambiguous. Never
	// replay or equate HTTP cancellation with stopping the guest process.
	out.Outcome = "unknown"
	out.MayStillBeRunning = true
	resp, err = r.proxy.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err = checkProxyResponse(resp, err); err != nil {
		out.Issue = err.Error()
		return out, nil
	}
	kind, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || kind != "text/event-stream" {
		out.Issue = "expected a Sandbox event stream"
		return out, nil
	}
	if err = collectOutput(resp.Body, out); err != nil {
		switch {
		case errors.Is(streamCtx.Err(), context.DeadlineExceeded):
			out.Issue = "wait deadline reached; command may still be running; do not automatically rerun"
		case errors.Is(streamCtx.Err(), context.Canceled):
			out.Issue = "request canceled; command may still be running; do not automatically rerun"
		default:
			out.Issue = err.Error()
		}
		return out, nil
	}
	out.Outcome = "exited"
	out.MayStillBeRunning = false
	// Preserve the terminal event even if the caller cancels after it arrives.
	// Reporting is bounded, uses the same auth/workspace, and is not retried.
	statusCtx, done := reportContext(ctx)
	defer done()
	resp, err = r.client.UpdateSandboxExec(statusCtx, id, out.ExecutionID, &client.UpdateSandboxExecParams{OwnerId: &workspace}, client.UpdateSandboxExecJSONRequestBody{ExitCode: out.ExitCode})
	updated, err := decode[sbx.SandboxExecUpdateResponse](resp, err, http.StatusOK)
	out.StatusPersisted = err == nil && updated.ExecId == out.ExecutionID && updated.SandboxId == id && updated.ExitCode != nil && *updated.ExitCode == *out.ExitCode
	if !out.StatusPersisted {
		out.Issue = "command exited; recording its completion failed"
	}
	return out, nil
}

// collectOutput handles the Sandbox protocol's output/exit/error SSE events.
// It follows SSE framing (comments, CRLF, multiline data, blank-line dispatch)
// without buffering the entire stream. The MCP SDK's parser is private and
// specific to JSON-RPC. Every line/event, retained output and total read is bounded.
func collectOutput(reader io.Reader, out *ExecResult) error {
	limited := &io.LimitedReader{R: reader, N: maxStreamBytes + 1}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 4096), maxEventBytes+1)
	var event string
	var data strings.Builder
	retained := 0
	var stdout, stderr strings.Builder
	defer func() { out.Stdout = stdout.String(); out.Stderr = stderr.String() }()
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if data.Len() == 0 {
				event = ""
				continue
			}
			done, err := consumeEvent(event, data.String(), out, &retained, &stdout, &stderr)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			event = ""
			data.Reset()
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event = value
		case "data":
			if data.Len()+len(value)+1 > maxEventBytes {
				return errors.New("Sandbox event exceeds the size limit; execution outcome unknown")
			}
			data.WriteString(value)
			data.WriteByte('\n')
		}
	}
	if limited.N <= 0 {
		return errors.New("Sandbox stream exceeds the read limit; execution outcome unknown")
	}
	if scanner.Err() != nil {
		return errors.New("Sandbox stream interrupted or oversized; execution outcome unknown")
	}
	return errors.New("Sandbox stream ended without an exit event; execution outcome unknown")
}

func consumeEvent(event, data string, out *ExecResult, retained *int, stdout, stderr *strings.Builder) (bool, error) {
	switch event {
	case "output":
		var value struct {
			Stream string  `json:"stream"`
			Data   *string `json:"data"`
		}
		if json.Unmarshal([]byte(data), &value) != nil || value.Data == nil || (value.Stream != "stdout" && value.Stream != "stderr") {
			return false, errors.New("invalid Sandbox output event; execution outcome unknown")
		}
		b := []byte(*value.Data)
		remaining := maxOutputBytes - *retained
		if len(b) > remaining {
			out.OutputTruncated = true
			b = trimIncompleteRune(b[:remaining])
		}
		*retained += len(b)
		if value.Stream == "stdout" {
			stdout.Write(b)
		} else {
			stderr.Write(b)
		}
	case "exit":
		var value struct {
			Code *int `json:"exit_code"`
		}
		if json.Unmarshal([]byte(data), &value) != nil || value.Code == nil || *value.Code < 0 || *value.Code > 255 {
			return false, errors.New("invalid Sandbox exit event; execution outcome unknown")
		}
		out.ExitCode = value.Code
		return true, nil
	case "error":
		// An arbitrary guest message can include credentials or command output.
		return false, errors.New("Sandbox reported an execution error; outcome unknown")
	default:
		return false, errors.New("unexpected Sandbox event; execution outcome unknown")
	}
	return false, nil
}
