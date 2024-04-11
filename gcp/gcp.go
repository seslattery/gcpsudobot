package gcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	. "github.com/seslattery/gcpsudobot/types"

	"github.com/seslattery/gcpsudobot/config"

	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

type ResourceType string

const (
	Projects      ResourceType = "projects"
	Organizations ResourceType = "organizations"
)

type Clock interface {
	now() time.Time
}

type Grouper interface {
	list(domain, requestor string) (*admin.Groups, error)
}

type IAMer interface {
	getIamPolicy(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
	setIamPolicy(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error)
}

type Googler interface {
	IAMer
	Grouper
	Clock
}

type Service struct {
	Googler
}

// Useful for tests to pass in a mock googler
func NewService(g Googler) *Service {
	return &Service{g}
}

func NewGoogleService() (*Service, error) {
	g, err := newGoogleService()
	if err != nil {
		return nil, err
	}
	return NewService(g), nil
}

// Pass in a Service from NewService() that fulfils the Grouper interface
func ListGoogleGroups(ctx context.Context, requestor Requestor, domain string, g Grouper) (Groups, error) {
	groups, err := g.list(string(requestor), domain)
	if err != nil {
		slog.Error(fmt.Sprintf("can't retrieve groups from google: %v", err))
		return nil, err
	}
	if groups == nil {
		return nil, fmt.Errorf("requestor isn't in any google groups")
	}
	gm := Groups{}
	for _, g := range groups.Groups {
		gm[Group(g.Email)] = struct{}{}
	}
	return gm, nil
}

// Attaches specific iam roles to a given user conditionally.
// Notably, this policy overwrites any existing policies.
// If you do not append your policy changes to an existing policy,
// it is very easy to get the gcp organization into a bad state.
// Please take a look at the comment in the critical section before making changes
// Can pass in a Service to satisfy IAMer
func BindIAMPolicy(ctx context.Context, r *EscalationApproval, g Googler) error {
	slog.Debug("Binding IAM Policy")

	userEmail := []string{fmt.Sprintf("user:%s", r.Requestor)}
	start := g.now()
	hoursFromNow := start.Add(time.Duration(config.Cfg.DurationOfGrantInHours) * time.Hour).Format(time.RFC3339)
	slog.Debug(fmt.Sprintf("Timestamp: %s", hoursFromNow))
	binding := &cloudresourcemanager.Binding{
		// Conditions cannot be set on primitive roles
		// Error 400: LintValidationUnits/BindingRoleAllowConditionCheck Error: Conditions can't be set on primitive roles
		Role:    string(r.Role),
		Members: userEmail,
		Condition: &cloudresourcemanager.Expr{
			Title:       fmt.Sprintf("Until: %s", hoursFromNow),
			Description: fmt.Sprintf("Grant %s on %s until %s", r.Role, r.Requestor, hoursFromNow),
			Expression:  fmt.Sprintf("request.time < timestamp(\"%s\")", hoursFromNow),
		},
	}
	getIamPolicyRequest := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{
			RequestedPolicyVersion: 3,
		},
	}
	//folderService := cloudresourcemanager.NewFoldersService(cloudResourceManagerService)
	for {
		existingPolicy, err := g.getIamPolicy(ctx, r.Resource, getIamPolicyRequest)
		if e, ok := err.(*googleapi.Error); ok {
			if e.Code == 409 {
				time.Sleep(5000 * time.Millisecond)
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("failed to retrieve iam policy: %v", err)
		}

		// CAUTION!!!
		// It is important that the existing policy is appeneded to.
		// If it is not, the new policy will overwrite the existing policy.
		// This could remove all existing permissions at the gcp org level!
		if existingPolicy == nil {
			return fmt.Errorf("no existing iam policy was found")
		}
		existingPolicy.Bindings = append(existingPolicy.Bindings, binding)
		// In order to use conditional IAM, must set version to 3
		// See https://cloud.google.com/iam/docs/policies#versions
		existingPolicy.Version = 3
		setIamPolicyRequest := &cloudresourcemanager.SetIamPolicyRequest{
			Policy: existingPolicy,
		}
		_, err = g.setIamPolicy(ctx, r.Resource, setIamPolicyRequest)
		if e, ok := err.(*googleapi.Error); ok {
			if e.Code == 409 {
				time.Sleep(5000 * time.Millisecond)
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("failed to set iam policy: %v", err)
		}
		return nil
	}
}

func parseResourceType(resource Resource) (ResourceType, error) {
	if strings.HasPrefix(string(resource), "projects/") {
		return Projects, nil
	}
	if strings.HasPrefix(string(resource), "organizations/") {
		return Organizations, nil
	}
	return "", errors.New("unexpected resource type, please check the configuration")
}

type googleService struct {
	iamClient    *cloudresourcemanager.Service
	groupsClient *admin.GroupsService
}

func newGoogleService() (*googleService, error) {
	ctx := context.Background()
	ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
		// User must be a GSuite admin.
		TargetPrincipal: config.Cfg.GsuiteAdmin,
		Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope},
	})
	if err != nil {
		slog.Error(fmt.Sprintf("can't initialize admin sdk %v", err))
		return nil, err
	}
	srv, err := admin.NewService(ctx, option.WithTokenSource(ts))
	if err != nil {
		slog.Error(fmt.Sprintf("can't initialize admin sdk %v", err))
		return nil, err
	}

	cloudResourceManagerService, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize google cloudresourcemanager: %v", err)
	}

	return &googleService{cloudResourceManagerService, admin.NewGroupsService(srv)}, nil
}

// GoogleClient is concrete implementation of IAMer and Grouper
// GetGroupMembership(g Grouper)
// ConditionalBindIAMPolicy(i IAMer)

func (g *googleService) list(domain, requestor string) (*admin.Groups, error) {
	return g.groupsClient.List().Domain(domain).UserKey(requestor).Do()
}

func (g *googleService) getIamPolicy(ctx context.Context, resource Resource, getiampolicyrequest *cloudresourcemanager.GetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	rscType, err := parseResourceType(resource)
	if err != nil {
		return nil, err
	}
	var gcpResource string
	switch rscType {
	case Projects:
		gcpResource = strings.Split(string(resource), "/")[1]
		return g.iamClient.Projects.GetIamPolicy(gcpResource, getiampolicyrequest).Context(ctx).Do()
	case Organizations:
		gcpResource = string(resource)
		return g.iamClient.Organizations.GetIamPolicy(gcpResource, getiampolicyrequest).Context(ctx).Do()
	}
	return nil, fmt.Errorf("unable to get iam policy")
}

// CAUTION!!!
// It is important that the existing IAM policy is appended to.
// If it is not, the new policy will overwrite the existing policy.
// This could remove all existing permissions at the gcp org level!
func (g *googleService) setIamPolicy(ctx context.Context, resource Resource, setiampolicyrequest *cloudresourcemanager.SetIamPolicyRequest) (*cloudresourcemanager.Policy, error) {
	rscType, err := parseResourceType(resource)
	if err != nil {
		return nil, err
	}
	if setiampolicyrequest == nil {
		return nil, fmt.Errorf("no existing policy was found")
	}
	if setiampolicyrequest.Policy == nil {
		return nil, fmt.Errorf("no existing policy was found")
	}
	var gcpResource string
	switch rscType {
	case Projects:
		gcpResource = strings.Split(string(resource), "/")[1]
		return g.iamClient.Projects.SetIamPolicy(gcpResource, setiampolicyrequest).Context(ctx).Do()
	case Organizations:
		gcpResource = string(resource)
		return g.iamClient.Organizations.SetIamPolicy(gcpResource, setiampolicyrequest).Context(ctx).Do()
	}
	return nil, fmt.Errorf("unable to set iam policy")
}

func (g *googleService) now() time.Time {
	return time.Now()
}
