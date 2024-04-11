package gcp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/seslattery/gcpsudobot/config"
	. "github.com/seslattery/gcpsudobot/types"

	"github.com/google/go-cmp/cmp"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
)

var CurrentTime = time.Date(2024, 04, 28, 00, 00, 00, 0, time.UTC)
var ExpiryTime = CurrentTime.Add(time.Duration(config.Cfg.DurationOfGrantInHours) * time.Hour).Format(time.RFC3339)

func TestListGoogleGroups(t *testing.T) {

	tests := []struct {
		name      string
		mock      *MockGoogler
		want      Groups
		wantError bool
	}{
		{
			"no groups found",
			&MockGoogler{ListF: func(domain, requestor string) (*admin.Groups, error) { return nil, nil }},
			//map[Group]struct{}{"test@gmail.com": {}, "test2@gmail.com": {}},
			nil,
			true,
		},
		{
			"can't reach google",
			&MockGoogler{ListF: func(domain, requestor string) (*admin.Groups, error) { return nil, fmt.Errorf("can't reach google") }},
			nil,
			true,
		},
		{
			"2 groups found",
			&MockGoogler{ListF: func(domain, requestor string) (*admin.Groups, error) {
				return &admin.Groups{Groups: []*admin.Group{
					{Email: "test1@gmail.com"},
					{Email: "test2@gmail.com"},
				}}, nil
			}},
			map[Group]struct{}{"test1@gmail.com": {}, "test2@gmail.com": {}},
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			got, err := ListGoogleGroups(ctx, "example.com", "sean.slattery203@gmail.com", tt.mock)
			if err != nil {
				if !tt.wantError {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("diff: %v", diff)
			}
		})
	}
}

func TestBindIAMPolicy(t *testing.T) {

	tests := []struct {
		name      string
		mock      *MockGoogler
		ea        *EscalationApproval
		wantError bool
	}{
		{
			"no policy found",
			&MockGoogler{
				NowF: func() time.Time { return CurrentTime },
				GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return nil, nil
				},
				SetIamPolicyF: func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return nil, nil
				}},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: Requestor("test@example.com"),
				},
				"default",
				Denied,
			},
			true,
		},
		{
			"add new iam bindings",
			&MockGoogler{
				NowF: func() time.Time { return CurrentTime },
				GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{Bindings: []*cloudresourcemanager.Binding{
						{
							Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
							Role:    "roles/owner",
						},
					}}, nil
				},
				// Spying on the setiampolicy request to ensure the iam binding was done correctly
				SetIamPolicyF: func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					got := setiampolicyrequest
					want := &cloudresourcemanager.SetIamPolicyRequest{Policy: &cloudresourcemanager.Policy{
						Version: 3,
						Bindings: []*cloudresourcemanager.Binding{
							{
								Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
								Role:    "roles/owner",
							},
							{
								Members: []string{"user:bob@gmail.com"},
								Role:    "roles/editor",
								Condition: &cloudresourcemanager.Expr{
									Description: fmt.Sprintf("Grant %s on %s until %s", "roles/editor", "bob@gmail.com", ExpiryTime),
									Expression:  fmt.Sprintf(`request.time < timestamp("%s")`, ExpiryTime),
									Title:       fmt.Sprintf("Until: %s", ExpiryTime),
								},
							},
						},
					},
					}

					if diff := cmp.Diff(got, want); diff != "" {
						return nil, fmt.Errorf("testing. unexpected diff: %v", diff)
					}
					return nil, nil
				}},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: Requestor("bob@gmail.com"),
					Role:      "roles/editor",
				},
				"default",
				Denied,
			},
			false,
		},
		{
			"merge duplicate role iam bindings",
			&MockGoogler{
				NowF: func() time.Time { return CurrentTime },
				GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					return &cloudresourcemanager.Policy{Bindings: []*cloudresourcemanager.Binding{
						{
							Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
							Role:    "roles/owner",
						},
						{
							Members: []string{"user:bar@gmail.com", "user:baz@gmail.com"},
							Role:    "roles/owner2",
						},
					}}, nil
				},
				// Spying on the setiampolicy request to ensure the iam binding was done correctly
				SetIamPolicyF: func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
					got := setiampolicyrequest
					want := &cloudresourcemanager.SetIamPolicyRequest{Policy: &cloudresourcemanager.Policy{
						Version: 3,
						Bindings: []*cloudresourcemanager.Binding{
							{
								Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
								Role:    "roles/owner",
							},
							{
								Members: []string{"user:bar@gmail.com", "user:baz@gmail.com"},
								Role:    "roles/owner2",
							},
							{
								Members: []string{"user:foo@gmail.com"},
								Role:    "roles/owner2",
								Condition: &cloudresourcemanager.Expr{
									Description: fmt.Sprintf("Grant %s on %s until %s", "roles/owner2", "foo@gmail.com", ExpiryTime),
									Expression:  fmt.Sprintf(`request.time < timestamp("%s")`, ExpiryTime),
									Title:       fmt.Sprintf("Until: %s", ExpiryTime),
								},
							},
						},
					},
					}

					if diff := cmp.Diff(got, want); diff != "" {
						return nil, fmt.Errorf("testing. unexpected diff: %v", diff)
					}
					return nil, nil
				}},
			&EscalationApproval{
				&EscalationRequest{
					Requestor: Requestor("foo@gmail.com"),
					Role:      "roles/owner2",
				},
				"default",
				Denied,
			},
			false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := BindIAMPolicy(ctx, tt.ea, tt.mock)
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantError && err == nil {
				t.Errorf("expected error not found")
			}
		})
	}
}

// TODO: Setup ADC test credentials for CI
//func TestGetIamPolicy(t *testing.T) {
//	t.Run("invalid resource type", func(t *testing.T) {
//		ctx := context.Background()
//		g, err := NewGoogleService()
//		if err != nil {
//			t.Errorf("couldn't start google service: %v", err)
//		}
//		_, err = g.getIamPolicy(ctx, Resource("not-valid"), nil)
//		if err == nil {
//			t.Errorf("expected err not nil")
//		}
//	})
//}
//
//// CAUTION!!!
//// This test is using a live google service. Do not pass in a valid resource / policy combo!
//// This could overwrite IAM permissions in GCP, potentially leaving us in a difficult to recover state
//// Generally wouldn't expect local ADC permissions to have permissions to do anything crazy, but you never know who is running this
//func TestSetIamPolicy(t *testing.T) {
//	t.Run("invalid resource type", func(t *testing.T) {
//		ctx := context.Background()
//		g, err := NewGoogleService()
//		if err != nil {
//			t.Errorf("couldn't start google service: %v", err)
//		}
//		_, err = g.setIamPolicy(ctx, Resource("not-valid"), nil)
//		if err == nil {
//			t.Errorf("expected err not nil")
//		}
//	})
//}
