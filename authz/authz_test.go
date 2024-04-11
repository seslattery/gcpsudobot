package authz

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/seslattery/gcpsudobot/gcp"
	. "github.com/seslattery/gcpsudobot/types"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
)

var TestPolicy = &PolicyRules{
	PolicyRules: []Rule{
		{
			Groups: map[Group]struct{}{
				"on-call@example.io": {},
			},
			Roles: map[Role]struct{}{
				"organizations/0000000000/roles/on_call_elevated": {},
			},
			Resources: map[Resource]struct{}{
				"organizations/0000000000": {},
			},
		},
		{
			Groups: map[Group]struct{}{
				"test-group-1": {},
				"test-group-2": {},
				"test-group-3": {},
			},
			Roles: map[Role]struct{}{
				"test-role-1": {},
				"test-role-2": {},
				"test-role-3": {},
			},
			Resources: map[Resource]struct{}{
				"test-resource-1": {},
				"test-resource-2": {},
				"test-resource-3": {},
			},
		},
		{
			Groups: map[Group]struct{}{
				"test-group-4": {},
				"test-group-5": {},
				"test-group-6": {},
			},
			Roles: map[Role]struct{}{
				"test-role-4": {},
			},
			Resources: map[Resource]struct{}{
				"test-resource-4": {},
			},
		},
		{
			Groups: map[Group]struct{}{
				"test-group-4": {},
			},
			Roles: map[Role]struct{}{
				"test-role-4": {},
				"test-role-5": {},
				"test-role-6": {},
			},
			Resources: map[Resource]struct{}{
				"test-resource-4": {},
			},
		},
		{
			Groups: map[Group]struct{}{
				"test-group-4": {},
			},
			Roles: map[Role]struct{}{
				"test-role-4": {},
			},
			Resources: map[Resource]struct{}{
				"test-resource-4": {},
				"test-resource-5": {},
				"test-resource-6": {},
			},
		},
	},
}

func TestAuthorizeRequest(t *testing.T) {
	tests := []struct {
		name     string
		mock     *gcp.MockGoogler
		input    *EscalationRequest
		expected bool
	}{
		{
			"happy path",
			// mock googler returns groups with "on-call@gmail.com"
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Role:      "organizations/0000000000/roles/on_call_elevated",
				Resource:  "organizations/0000000000",
			},
			true,
		},
		{
			"not a valid domain on requestor",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@foobarbaz.io",
				Role:      "organizations/0000000000/roles/on_call_elevated",
				Resource:  "organizations/0000000000",
			},
			false,
		},
		{
			"missing @ on otherwise valid domain on requestor",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user-gmail.com",
				Role:      "organizations/0000000000/roles/on_call_elevated",
				Resource:  "organizations/0000000000",
			},
			false,
		},
		{
			"wrong group for role/resource",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user-gmail.com",
				Role:      "test-role-4",
				Resource:  "test-resource-4",
			},
			false,
		},
		{
			"wrong role",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Role:      "organizations/0000000000/roles/on_call_elevated-2",
				Resource:  "organizations/0000000000",
			},
			false,
		},
		{
			"wrong resource",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Role:      "organizations/0000000000/roles/on_call_elevated",
				Resource:  "organizations/0000000000-2",
			},
			false,
		},
		{
			"no resource",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Role:      "organizations/0000000000/roles/on_call_elevated",
			},
			false,
		},
		{
			"no role",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Resource:  "organizations/0000000000",
			},
			false,
		},
		{
			"no requestor",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Resource: "organizations/0000000000",
				Role:     "organizations/0000000000/roles/on_call_elevated",
			},
			false,
		},
		{
			"happy path again different requestor",
			gcp.NewMockGoogler(),
			&EscalationRequest{
				Requestor: "foobarbaz@gmail.com",
				Resource:  "organizations/0000000000",
				Role:      "organizations/0000000000/roles/on_call_elevated",
			},
			true,
		},
		{
			"empty groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return &admin.Groups{Groups: []*admin.Group{}}, nil
				},
			},
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Resource:  "organizations/0000000000",
				Role:      "organizations/0000000000/roles/on_call_elevated",
			},
			false,
		},
		{
			"nil groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return nil, nil
				},
			},
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Resource:  "organizations/0000000000",
				Role:      "organizations/0000000000/roles/on_call_elevated",
			},
			false,
		},
		{
			"error when getting groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return nil, fmt.Errorf("testing error")
				},
			},
			&EscalationRequest{
				Requestor: "user@gmail.com",
				Resource:  "organizations/0000000000",
				Role:      "organizations/0000000000/roles/on_call_elevated",
			},
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			b, err := AuthorizeRequest(ctx, TestPolicy, tt.input, gcp.NewService(tt.mock))
			if b != tt.expected {
				t.Log(err)
				t.Errorf("got %v, want %v", b, tt.expected)
			}
		})
	}
}

func TestAuthorizeApprovalAndGrantIAM(t *testing.T) {
	tests := []struct {
		name        string
		mock        *gcp.MockGoogler
		input       *EscalationApproval
		expectedErr bool
	}{
		{
			"happy path",
			// mock googler returns groups with "on-call@gmail.com"
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Role:      "organizations/0000000000/roles/on_call_elevated",
					Resource:  "organizations/0000000000",
				},
				"approver@gmail.com",
				Approved,
			},
			false,
		},
		{
			"not a valid domain on requestor",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@foobarbaz.io",
					Role:      "organizations/0000000000/roles/on_call_elevated",
					Resource:  "organizations/0000000000",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"missing @ on otherwise valid domain on requestor",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user-gmail.com",
					Role:      "organizations/0000000000/roles/on_call_elevated",
					Resource:  "organizations/0000000000",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"wrong group for role/resource",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user-gmail.com",
					Role:      "test-role-4",
					Resource:  "test-resource-4",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"wrong role",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Role:      "organizations/0000000000/roles/on_call_elevated-2",
					Resource:  "organizations/0000000000",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"wrong resource",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Role:      "organizations/0000000000/roles/on_call_elevated",
					Resource:  "organizations/0000000000-2",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"no resource",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"no role",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"no requestor",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Resource: "organizations/0000000000",
					Role:     "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"happy path again different requestor",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "foobarbaz@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			false,
		},
		{
			"empty groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return &admin.Groups{Groups: []*admin.Group{}}, nil
				},
			},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"nil groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return nil, nil
				},
			},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"error when getting groups",
			&gcp.MockGoogler{
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return nil, fmt.Errorf("testing error")
				},
			},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			// denial shouldn't throw an error, it just doesn't call BindIAM
			"denial",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "foobarbaz@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Denied,
			},
			false,
		},
		{
			"not a valid domain for approver",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "foobarbaz@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@foobarbaz.com",
				Approved,
			},
			true,
		},
		{
			"missing @ on otherwise valid domain on approver",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "foobarbaz@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver-gmail.com",
				Approved,
			},
			true,
		},
		{
			"requestor cannot self approve",
			gcp.NewMockGoogler(),
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "foobarbaz@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"foobarbaz@gmail.com",
				Approved,
			},
			true,
		},
		{
			"error when getting IAM",
			&gcp.MockGoogler{
				NowF: func() time.Time { return time.Now() },
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return &admin.Groups{Groups: []*admin.Group{{Email: "on-call@example.io"}}}, nil
				},
				// this is returning a policy and an error, making sure we check the error and stop
				GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{Bindings: []*cloudresourcemanager.Binding{
						{
							Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
							Role:    "roles/owner",
						},
					}}, fmt.Errorf("testing iam error")
				},
			},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
		{
			"error when setting IAM",
			&gcp.MockGoogler{
				NowF: func() time.Time { return time.Now() },
				ListF: func(domain, requestor string) (*admin.Groups, error) {
					return &admin.Groups{Groups: []*admin.Group{{Email: "on-call@example.io"}}}, nil
				},
				// this is returning a policy and an error, making sure we check the error and stop
				GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{Bindings: []*cloudresourcemanager.Binding{
						{
							Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
							Role:    "roles/owner",
						},
					}}, nil
				},
				SetIamPolicyF: func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return nil, fmt.Errorf("testing set iam policy")
				},
			},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "user@gmail.com",
					Resource:  "organizations/0000000000",
					Role:      "organizations/0000000000/roles/on_call_elevated",
				},
				"approver@gmail.com",
				Approved,
			},
			true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := AuthorizeApprovalAndGrantIAM(ctx, TestPolicy, tt.input, gcp.NewService(tt.mock))
			if err != nil {
				if !tt.expectedErr {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestAuthz(t *testing.T) {
	tests := []struct {
		name     string
		input    *EscalationRequest
		expected bool
	}{
		{"test hub", &EscalationRequest{
			Groups:   map[Group]struct{}{"on-call@example.io": {}},
			Role:     "organizations/0000000000/roles/on_call_elevated",
			Resource: "organizations/0000000000",
		}, true},
		{"test 1-2-3", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-1": {}},
			Role:     "test-role-2",
			Resource: "test-resource-3",
		}, true},
		{"test 3-2-1", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-3": {}},
			Role:     "test-role-2",
			Resource: "test-resource-1",
		}, true},
		{"test 4-4-4", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-4": {}},
			Role:     "test-role-4",
			Resource: "test-resource-4",
		}, true},
		{"test 5-4-4", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-5": {}},
			Role:     "test-role-4",
			Resource: "test-resource-4",
		}, true},
		{"test 4-5-6", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-4": {}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
		{"test 5-5-6", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-5": {}},
			Role:     "test-role-5",
			Resource: "test-resource-6",
		}, false},
		{"test 6-5-4", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-6": {}},
			Role:     "test-role-5",
			Resource: "test-resource-4",
		}, false},
		{"test 4-5-4", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-4": {}},
			Role:     "test-role-5",
			Resource: "test-resource-4",
		}, true},
		{"test 2-3-4", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-2": {}},
			Role:     "test-role-3",
			Resource: "test-resource-4",
		}, false},
		{"test 1-2-5", &EscalationRequest{
			Groups:   map[Group]struct{}{"test-group-1": {}},
			Role:     "test-role-2",
			Resource: "test-resource-5",
		}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			b := authz(TestPolicy, tt.input)
			if b != tt.expected {
				t.Errorf("got %v, want %v", b, tt.expected)
			}
		})
	}
}
func TestListOptions(t *testing.T) {
	t.Run("ListOptions", func(t *testing.T) {
		groups, roles, resources := TestPolicy.ListOptions()

		wantedGroups := map[Group]struct{}{"on-call@example.io": {}, "test-group-1": {}, "test-group-2": {}, "test-group-3": {}, "test-group-4": {}, "test-group-5": {}, "test-group-6": {}}
		wantedRoles := map[Role]struct{}{"on-call@example.io": {}, "test-role-1": {}, "test-role-2": {}, "test-role-3": {}, "test-role-4": {}, "test-role-5": {}, "test-role-6": {}}
		wantedResources := map[Resource]struct{}{"on-call@example.io": {}, "test-resource-1": {}, "test-resource-2": {}, "test-resource-3": {}, "test-resource-4": {}, "test-resource-5": {}, "test-resource-6": {}}

		if reflect.DeepEqual(wantedGroups, groups) {
			t.Errorf("got %v, want %v", groups, wantedGroups)
		}
		if reflect.DeepEqual(wantedRoles, roles) {
			t.Errorf("got %v, want %v", roles, wantedRoles)
		}
		if reflect.DeepEqual(wantedResources, resources) {
			t.Errorf("got %v, want %v", resources, wantedResources)
		}

	})
}
