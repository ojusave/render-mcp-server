package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/render-oss/render-mcp-server/pkg/client"
	sbx "github.com/render-oss/render-mcp-server/pkg/client/sandboxes"
	"github.com/render-oss/render-mcp-server/pkg/mcpserver"
	"github.com/render-oss/render-mcp-server/pkg/pointers"
	"github.com/render-oss/render-mcp-server/pkg/validate"
)

const maxConcurrentCalls = 16

func Tools(c *client.ClientWithResponses) []server.ServerTool {
	return definitions(NewRepo(c))
}

// WithLimits wraps a group of Sandbox tools with a shared concurrency limit
// and per-call deadline. Apply it after workspace scoping so resolution is
// included in the deadline.
func WithLimits(tools []server.ServerTool) []server.ServerTool {
	slots := make(chan struct{}, maxConcurrentCalls)
	for i := range tools {
		handler := tools[i].Handler
		tools[i].Handler = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
			defer cancel()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			default:
				return mcp.NewToolResultError("Sandbox tools are busy; no operation started"), nil
			}
			if ctx.Err() != nil {
				return mcp.NewToolResultError("request canceled before Sandbox operation started"), nil
			}
			return handler(ctx, req)
		}
	}
	return tools
}

func annotation(title string, readOnly, destructive, idempotent bool) mcp.ToolOption {
	return mcp.WithToolAnnotation(mcp.ToolAnnotation{Title: title, ReadOnlyHint: pointers.From(readOnly),
		DestructiveHint: pointers.From(destructive), IdempotentHint: pointers.From(idempotent), OpenWorldHint: pointers.From(true)})
}

func sandboxIDParam() mcp.ToolOption {
	return mcp.WithString("sandboxId", mcp.Required(), mcp.Description("Exact sandbox ID returned by create_sandbox or list_sandboxes."), mcp.MaxLength(128))
}

func filePathParam() mcp.ToolOption {
	return mcp.WithString("path", mcp.Required(), mcp.Description("A clean file path. Absolute paths address the sandbox root; relative paths start in its home directory. No shell expansion."), mcp.MaxLength(4096))
}

func definitions(r *Repo) []server.ServerTool {
	return []server.ServerTool{
		{
			Tool: mcp.NewTool("create_sandbox",
				mcp.WithDescription("Create a persistent Render Sandbox to run code. Returns its ID and current state promptly; use get_sandbox until running before executing. Defaults: starter plan, 600-second lifetime, and deny-all outbound networking. Terminate after retrieving wanted files. Creation consumes resources; do not retry an ambiguous response automatically."),
				annotation("Create sandbox", false, false, false),
				mcp.WithInteger("timeout_seconds", mcp.DefaultNumber(600), mcp.Min(1), mcp.Max(86400), mcp.Description("Sandbox lifetime in seconds. All processes and files are removed when it expires.")),
				mcp.WithString("plan", mcp.DefaultString(string(sbx.Starter)), mcp.Enum(mcpserver.EnumValuesFromClientType(sbx.SandboxPlanValues()...)...)),
				mcp.WithString("region", mcp.Enum(mcpserver.RegionEnumValues()...), mcp.Description("Omit to use the workspace default region.")),
				mcp.WithString("network_policy", mcp.DefaultString(string(sbx.DenyAll)), mcp.Enum(string(sbx.DenyAll), string(sbx.AllowAll), string(sbx.AllowList))),
				mcp.WithArray("allowed_domains", mcp.WithStringItems(), mcp.MaxItems(100), mcp.Description("Required only for allow-list. Exact hostnames or leftmost wildcards such as *.example.com; HTTPS only.")),
			),
			Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				in, err := parseCreate(req)
				if err != nil {
					return toolResult(nil, err)
				}
				value, err := r.Create(ctx, in)
				return toolResult(value, err)
			},
		},
		{
			Tool: mcp.NewTool("get_sandbox", mcp.WithDescription("Inspect one sandbox by exact ID in the selected workspace, including readiness or terminal state. This reports sandbox state, not individual command completion."), annotation("Get sandbox", true, false, true), sandboxIDParam()),
			Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id, err := parseID(req)
				if err == nil {
					err = onlyParams(req, "sandboxId")
				}
				if err != nil {
					return toolResult(nil, err)
				}
				value, err := r.Get(ctx, id)
				return toolResult(value, err)
			},
		},
		{
			Tool: mcp.NewTool("list_sandboxes", mcp.WithDescription("List one page of sandboxes in the selected workspace. Pass next_cursor as cursor until an empty page to finish. All statuses are included unless filtered."), annotation("List sandboxes", true, false, true),
				mcp.WithInteger("limit", mcp.DefaultNumber(20), mcp.Min(1), mcp.Max(100)),
				mcp.WithString("cursor", mcp.Description("Cursor from the preceding page."), mcp.MaxLength(512)),
				mcp.WithArray("statuses", mcp.WithStringItems(), mcp.MaxItems(20), mcp.Description("Optional exact status values. Omit for every status, including terminated."))),
			Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				params, err := parseList(req)
				if err != nil {
					return toolResult(nil, err)
				}
				value, err := r.List(ctx, params)
				return toolResult(value, err)
			},
		},
		{
			Tool: mcp.NewTool("run_sandbox_command",
				mcp.WithDescription("Run a bash command in a sandbox. Suspended sandboxes resume during bounded connection setup. Waits up to 30 seconds and retains at most 64 KiB of combined stdout/stderr. A wait timeout or disconnected call DOES NOT stop the command. Unknown outcomes may still be running; do not automatically rerun. Returns sandbox/execution IDs and an exit code only when observed. Background-result recovery is not supported. Command execution can modify or delete files and use allowed network access."),
				annotation("Run sandbox command", false, true, false), sandboxIDParam(),
				mcp.WithString("command", mcp.Required(), mcp.MaxLength(maxCommandBytes), mcp.Description("Shell command to execute with bash. Maximum 16 KiB UTF-8.")),
				mcp.WithInteger("wait_timeout_seconds", mcp.DefaultNumber(30), mcp.Min(1), mcp.Max(30), mcp.Description("How long to wait for the stream, not a remote process deadline."))),
			Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id, err := parseID(req)
				if err == nil {
					err = onlyParams(req, "sandboxId", "command", "wait_timeout_seconds")
				}
				if err != nil {
					return toolResult(nil, err)
				}
				command, err := requiredText(req, "command", maxCommandBytes, false)
				if err != nil {
					return toolResult(nil, err)
				}
				wait, err := integer(req, "wait_timeout_seconds", 30, 1, 30)
				if err != nil {
					return toolResult(nil, err)
				}
				value, err := r.Exec(ctx, id, command, time.Duration(wait)*time.Second)
				return toolResult(value, err)
			},
		},
		fileTool(r, false),
		fileTool(r, true),
		{
			Tool: mcp.NewTool("terminate_sandbox", mcp.WithDescription("Terminate a sandbox in the selected workspace. Stops every process and permanently removes its files. Retrieve wanted files first. Reports whether termination was accepted and independently verified."), annotation("Terminate sandbox", false, true, true), sandboxIDParam()),
			Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				id, err := parseID(req)
				if err == nil {
					err = onlyParams(req, "sandboxId")
				}
				if err != nil {
					return toolResult(nil, err)
				}
				value, err := r.Terminate(ctx, id)
				return toolResult(value, err)
			},
		},
	}
}

func fileTool(r *Repo, write bool) server.ServerTool {
	name, desc, title := "read_sandbox_file", "Read a single UTF-8 text file from a sandbox, up to 64 KiB. Reports truncation. Binary files and directory archives require the CLI or SDK. Content is returned to the agent, not saved to the user's computer.", "Read sandbox file"
	options := []mcp.ToolOption{sandboxIDParam(), filePathParam()}
	if write {
		name, desc, title = "write_sandbox_file", "Write a UTF-8 text file of at most 64 KiB. Overwrites an existing file at the exact path. No shell expansion or archive extraction. Do not automatically retry an ambiguous write.", "Write sandbox file"
		options = append(options, mcp.WithString("content", mcp.Required(), mcp.MaxLength(maxFileBytes), mcp.Description("UTF-8 text to write, at most 64 KiB. Empty content creates an empty file.")))
	}
	options = append(options, mcp.WithDescription(desc), annotation(title, !write, write, !write))
	return server.ServerTool{Tool: mcp.NewTool(name, options...), Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, err := parseID(req)
		keys := []string{"sandboxId", "path"}
		if write {
			keys = append(keys, "content")
		}
		if err == nil {
			err = onlyParams(req, keys...)
		}
		if err != nil {
			return toolResult(nil, err)
		}
		p, err := requiredText(req, "path", 4096, false)
		if err == nil && (path.Clean(p) != p || p == ".." || strings.HasPrefix(p, "../")) {
			err = errors.New("path must be clean with no parent traversal or redundant separators")
		}
		if err != nil {
			return toolResult(nil, err)
		}
		var content *string
		if write {
			text, err := requiredText(req, "content", maxFileBytes, true)
			if err != nil {
				return toolResult(nil, err)
			}
			content = &text
		}
		value, err := r.File(ctx, id, p, content)
		return toolResult(value, err)
	}}
}

func toolResult(value any, err error) (*mcp.CallToolResult, error) {
	failed := err != nil
	if err != nil {
		value = map[string]any{"error": err.Error(), "result": value}
	}
	switch v := value.(type) {
	case *ExecResult:
		failed = v.Outcome != "exited" || (v.ExitCode != nil && *v.ExitCode != 0)
	case *FileResult:
		failed = v.Outcome == "unknown"
	case *TerminateResult:
		failed = !v.VerifiedTerminated
	}
	data, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return mcp.NewToolResultError("cannot encode Sandbox response"), nil
	}
	result := mcp.NewToolResultText(string(data))
	result.IsError = failed
	return result, nil
}

var sandboxIDPattern = regexp.MustCompile(`^sbx-[a-z0-9]+$`)

func parseID(req mcp.CallToolRequest) (string, error) {
	value, err := requiredText(req, "sandboxId", 128, false)
	if err == nil && !sandboxIDPattern.MatchString(value) {
		return "", errors.New("invalid sandboxId")
	}
	return value, err
}

func requiredText(req mcp.CallToolRequest, name string, limit int, allowEmpty bool) (string, error) {
	value, err := validate.RequiredToolParam[string](req, name)
	if err != nil {
		return "", err
	}
	if (!allowEmpty && strings.TrimSpace(value) == "") || len(value) > limit || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
		return "", fmt.Errorf("%s must be valid UTF-8 without NUL, at most %d bytes%s", name, limit, map[bool]string{false: ", and not empty"}[allowEmpty])
	}
	return value, nil
}

func integer(req mcp.CallToolRequest, name string, def, min, max int) (int, error) {
	value, ok, err := validate.OptionalToolParam[float64](req, name)
	if err != nil {
		return 0, err
	}
	if !ok {
		return def, nil
	}
	if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < float64(min) || value > float64(max) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", name, min, max)
	}
	return int(value), nil
}

func onlyParams(req mcp.CallToolRequest, allowed ...string) error {
	for name := range req.GetArguments() {
		if name != "workspaceId" && !slices.Contains(allowed, name) {
			return errors.New("unsupported Sandbox parameter; use the tool's declared inputs")
		}
	}
	return nil
}

func parseCreate(req mcp.CallToolRequest) (client.CreateSandboxJSONRequestBody, error) {
	var in client.CreateSandboxJSONRequestBody
	if err := onlyParams(req, "timeout_seconds", "plan", "region", "network_policy", "allowed_domains"); err != nil {
		return in, err
	}
	timeout, err := integer(req, "timeout_seconds", 600, 1, 86400)
	if err != nil {
		return in, err
	}
	in.TimeoutSeconds = &timeout
	plan, ok, err := validate.OptionalToolParam[string](req, "plan")
	if err != nil {
		return in, err
	}
	if !ok {
		plan = string(sbx.Starter)
	}
	p := sbx.SandboxPlan(plan)
	if !p.Valid() {
		return in, errors.New("invalid sandbox plan")
	}
	in.Plan = &p
	region, ok, err := validate.OptionalToolParam[string](req, "region")
	if err != nil {
		return in, err
	}
	if ok {
		if !slices.Contains(mcpserver.RegionEnumValues(), region) {
			return in, errors.New("invalid Render region")
		}
		in.Region = &region
	}
	policy, ok, err := validate.OptionalToolParam[string](req, "network_policy")
	if err != nil {
		return in, err
	}
	if !ok {
		policy = string(sbx.DenyAll)
	}
	typ := sbx.SandboxNetworkPolicyType(policy)
	if !typ.Valid() {
		return in, errors.New("invalid network policy")
	}
	domains, present, err := validate.OptionalToolArrayParam[string](req, "allowed_domains")
	if err != nil {
		return in, err
	}
	if typ != sbx.AllowList && present {
		return in, errors.New("allowed_domains requires network_policy allow-list")
	}
	if typ == sbx.AllowList && (len(domains) == 0 || len(domains) > 100) {
		return in, errors.New("allow-list requires 1 to 100 allowed_domains")
	}
	network := sbx.SandboxNetworkPolicyPOST{Type: &typ}
	if typ == sbx.AllowList {
		seen := map[string]bool{}
		rules := make([]sbx.SandboxEgressRule, 0, len(domains))
		for _, domain := range domains {
			if !validDomain(domain) || seen[strings.ToLower(domain)] {
				return in, errors.New("allowed_domains must contain distinct hostnames or leftmost wildcard domains")
			}
			seen[strings.ToLower(domain)] = true
			protocol := sbx.SandboxEgressRuleProtocol("https")
			rules = append(rules, sbx.SandboxEgressRule{Domain: domain, Protocol: &protocol})
		}
		network.Rules = &rules
	}
	in.NetworkPolicy = &network
	return in, nil
}

func validDomain(domain string) bool {
	host := strings.TrimPrefix(domain, "*.")
	if len(host) == 0 || len(host) > 253 || net.ParseIP(host) != nil {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range strings.ToLower(label) {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func parseList(req mcp.CallToolRequest) (client.ListSandboxesParams, error) {
	var params client.ListSandboxesParams
	if err := onlyParams(req, "limit", "cursor", "statuses"); err != nil {
		return params, err
	}
	limit, err := integer(req, "limit", 20, 1, 100)
	if err != nil {
		return params, err
	}
	params.Limit = &limit
	cursor, ok, err := validate.OptionalToolParam[string](req, "cursor")
	if err != nil {
		return params, err
	}
	if len(cursor) > 512 || strings.ContainsRune(cursor, 0) {
		return params, errors.New("invalid cursor")
	}
	if ok && cursor != "" {
		params.Cursor = &cursor
	}
	statuses, ok, err := validate.OptionalToolArrayParam[string](req, "statuses")
	if err != nil {
		return params, err
	}
	if len(statuses) > 20 {
		return params, errors.New("too many statuses")
	}
	if ok && len(statuses) > 0 {
		values := make([]sbx.SandboxStatus, 0, len(statuses))
		for _, status := range statuses {
			value := sbx.SandboxStatus(status)
			if !value.Valid() {
				return params, errors.New("invalid sandbox status")
			}
			values = append(values, value)
		}
		params.Status = &values
	}
	return params, nil
}
