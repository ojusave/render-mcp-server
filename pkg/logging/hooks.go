package logging

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func AddHooks(hooks *server.Hooks) {
	if !enabled() {
		return
	}

	hooks.AddBeforeCallTool(func(_ context.Context, _ any, message *mcp.CallToolRequest) {
		Info("tool call start name=%s", message.Params.Name)
	})

	hooks.AddAfterCallTool(func(_ context.Context, _ any, message *mcp.CallToolRequest, result any) {
		// The SDK hook receives CallToolResult for synchronous calls or CreateTaskResult
		// for task creation. Our tools currently run synchronously, so inspect their
		// results for errors. Revisit logging if we add tasks: task creation succeeding
		// does not mean the underlying operation succeeded.
		if result, ok := result.(*mcp.CallToolResult); ok && result != nil && result.IsError {
			if isSandboxTool(message.Params.Name) {
				// Sandbox failures can retain command output or file contents.
				Error("tool call failed name=%s", message.Params.Name)
			} else {
				Error("tool call failed name=%s error=%s", message.Params.Name, toolResultText(result))
			}
			return
		}
		Info("tool call ok name=%s", message.Params.Name)
	})

	hooks.AddOnError(func(_ context.Context, _ any, method mcp.MCPMethod, _ any, err error) {
		Error("mcp error method=%s err=%v", method, err)
	})
}

func toolResultText(result *mcp.CallToolResult) string {
	for _, content := range result.Content {
		if text, ok := mcp.AsTextContent(content); ok && text.Text != "" {
			return text.Text
		}
	}
	return "unknown tool error"
}

func isSandboxTool(name string) bool {
	switch name {
	case "create_sandbox", "get_sandbox", "list_sandboxes", "run_sandbox_command", "read_sandbox_file", "write_sandbox_file", "terminate_sandbox":
		return true
	default:
		return false
	}
}
