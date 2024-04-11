package gcp

import (
	"context"
	"time"

	. "github.com/seslattery/gcpsudobot/types"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
)

type MockGoogler struct {
	ListF         func(domain, requestor string) (*admin.Groups, error)
	GetIamPolicyF func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	SetIamPolicyF func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	NowF          func() time.Time
}

func (m *MockGoogler) list(domain, requestor string) (*admin.Groups, error) {
	return m.ListF(domain, requestor)
}
func (m *MockGoogler) getIamPolicy(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	return m.GetIamPolicyF(ctx, resource, getiampolicyrequest)
}
func (m *MockGoogler) setIamPolicy(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	return m.SetIamPolicyF(ctx, resource, setiampolicyrequest)
}
func (m *MockGoogler) now() time.Time {
	return m.NowF()
}

func NewMockGoogler() *MockGoogler {
	return &MockGoogler{
		NowF: func() time.Time { return time.Now() },
		ListF: func(domain, requestor string) (*admin.Groups, error) {
			return &admin.Groups{Groups: []*admin.Group{
				{Email: "prod-db-access@gmail.com"},
				{Email: "on-call@example.io"},
			}}, nil
		},
		GetIamPolicyF: func(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
			return &cloudresourcemanager.Policy{Bindings: []*cloudresourcemanager.Binding{
				{
					Members: []string{"user:bob@gmail.com", "user:foo@gmail.com", "user:bar@gmail.com", "user:baz@gmail.com"},
					Role:    "roles/owner",
				},
			}}, nil
		},
		SetIamPolicyF: func(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
			return nil, nil
		},
	}
}
