package keyvalue

import (
	"context"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/render-oss/render-mcp-server/pkg/client"
	"github.com/render-oss/render-mcp-server/pkg/fakes"
	"github.com/render-oss/render-mcp-server/pkg/pointers"
	"github.com/render-oss/render-mcp-server/pkg/session"
	"github.com/render-oss/render-mcp-server/pkg/validate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateKeyValueToolSchemaDefault(t *testing.T) {
	fakeClient := &fakes.FakeKeyValueRepoClient{}
	repo := NewRepo(fakeClient)
	tool := createKeyValue(repo)

	planProp := tool.Tool.InputSchema.Properties["plan"].(map[string]any)
	assert.Equal(t, "free", planProp["default"])
}

func TestCreateKeyValueTool(t *testing.T) {
	ownerId := "own-123456"
	kvName := "test-keyvalue"

	tests := []struct {
		name         string
		plan         *string
		expectedPlan client.KeyValuePlan
	}{
		{
			name:         "Create key value with no plan defaults to free",
			plan:         nil,
			expectedPlan: client.KeyValuePlanFree,
		},
		{
			name:         "Create key value with free plan",
			plan:         pointers.From("free"),
			expectedPlan: client.KeyValuePlanFree,
		},
		{
			name:         "Create key value with starter plan",
			plan:         pointers.From("starter"),
			expectedPlan: client.KeyValuePlanStarter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := &fakes.FakeKeyValueRepoClient{}
			repo := NewRepo(fakeClient)

			fakeClient.CreateKeyValueWithResponseReturns(&client.CreateKeyValueResponse{
				JSON201: &client.KeyValueDetail{
					Id:   "kv-123",
					Name: kvName,
				},
				HTTPResponse: &http.Response{
					StatusCode: 201,
				},
			}, nil)

			ctx := createTestContext(t, ownerId)

			args := map[string]any{
				"name": kvName,
			}
			if tt.plan != nil {
				args["plan"] = *tt.plan
			}
			request := mcp.CallToolRequest{}
			request.Params.Arguments = args

			tool := createKeyValue(repo)
			result, err := tool.Handler(ctx, request)

			require.NoError(t, err)
			require.NotNil(t, result)
			require.False(t, result.IsError, "expected no error but got: %v", result.Content)

			assert.Equal(t, 1, fakeClient.CreateKeyValueWithResponseCallCount())
			_, requestBody, _ := fakeClient.CreateKeyValueWithResponseArgsForCall(0)
			assert.Equal(t, kvName, requestBody.Name)
			assert.Equal(t, ownerId, requestBody.OwnerId)
			assert.Equal(t, tt.expectedPlan, requestBody.Plan)
		})
	}
}

func createTestContext(t *testing.T, workspaceID string) context.Context {
	t.Helper()
	t.Setenv("RENDER_CONFIG_PATH", filepath.Join(t.TempDir(), "mcp-server.yaml"))
	ctx := session.ContextWithStdioSession(context.Background())
	sess := session.FromContext(ctx)
	sess.SetWorkspace(ctx, workspaceID)
	return ctx
}

// TestCreateKeyValueToolPlanEnumIsAccepted pins the create_key_value plan
// parameter to the generated enum. The schema is built from
// KeyValuePlanValues() while the handler validates against the generated
// Valid(), so the two can diverge, and requiring a spec-based memory-size name
// catches a schema pinned to a hardcoded list.
func TestCreateKeyValueToolPlanEnumIsAccepted(t *testing.T) {
	repo := NewRepo(&fakes.FakeKeyValueRepoClient{})
	tool := createKeyValue(repo)

	planProp, ok := tool.Tool.InputSchema.Properties["plan"].(map[string]any)
	require.True(t, ok, "create_key_value has no plan property")
	plans, ok := planProp["enum"].([]string)
	require.True(t, ok, "create_key_value plan property has no string enum")

	for _, plan := range plans {
		_, err := validate.KeyValuePlan(plan)
		assert.NoError(t, err, "advertised plan %q is rejected by validate.KeyValuePlan", plan)
	}

	specBased := regexp.MustCompile(`^[0-9]+(mb|g)$`)
	assert.True(t, slices.ContainsFunc(plans, specBased.MatchString),
		"no spec-based plan name advertised, got %v", plans)
}
