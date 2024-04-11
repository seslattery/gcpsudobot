package authz

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/seslattery/gcpsudobot/config"
	"github.com/seslattery/gcpsudobot/gcp"
	. "github.com/seslattery/gcpsudobot/types"
)

func AuthorizeRequest(ctx context.Context, p *PolicyRules, r *EscalationRequest, gs *gcp.Service) (bool, error) {
	if !strings.HasSuffix(string(r.Requestor), fmt.Sprintf("@%s", config.Cfg.ValidDomain)) {
		return false, fmt.Errorf("unauthorized user, not from %s: %v", config.Cfg.ValidDomain, r.Requestor)
	}
	groups, err := gcp.ListGoogleGroups(ctx, r.Requestor, config.Cfg.ValidDomain, gs)
	r.Groups = groups
	if err != nil {
		return false, fmt.Errorf("can't get group membership for user: %v", r.Requestor)
	}
	if authz(p, r) {
		return true, nil
	}
	return false, nil
}

// Validates the EscalationApproval, and if succesful, proceeds to generate a conditional IAM Grant
func AuthorizeApprovalAndGrantIAM(ctx context.Context, p *PolicyRules, a *EscalationApproval, gs *gcp.Service) error {
	r := a.EscalationRequest
	// This is a double check on the authorization from slack, incase that's somehow intercepted etc, the authz check happens within the approval call
	ok, err := AuthorizeRequest(ctx, p, r, gs)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("double checking authorization failed")
	}

	if !strings.HasSuffix(a.Approver, fmt.Sprintf("@%s", config.Cfg.ValidDomain)) {
		return fmt.Errorf("unauthorized user, not from example.io: %v", a.Approver)
	}

	// Ensure requestor is not approver
	if a.Approver == string(a.Requestor) {
		return fmt.Errorf("self approval not allowed for this rule")
	}
	slog.Warn(a.String())
	if a.Status == Approved {
		err := gcp.BindIAMPolicy(ctx, a, gs)
		if err != nil {
			return fmt.Errorf("couldn't set IAM policy: %v", err)
		}
	}
	return nil
}

func authz(p *PolicyRules, r *EscalationRequest) bool {
	for _, pol := range p.PolicyRules {
		for g := range r.Groups {
			if _, ok := pol.Groups[g]; !ok {
				continue
			}
			if _, ok := pol.Roles[r.Role]; !ok {
				continue
			}
			if _, ok := pol.Resources[r.Resource]; ok {
				return true
			}
		}

	}
	return false
}
