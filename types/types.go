package types

import (
	"fmt"
)

type Approval bool

const (
	Approved Approval = true
	Denied   Approval = false
)

func (a Approval) String() string {
	if a {
		return "Approver"
	}
	return "Denier"
}

func (a Approval) ApprovalText(duration int) string {
	if a {
		return fmt.Sprintf("Approved. The role has been granted for %v hours.", duration)
	}
	return "The Request has been denied."
}

type Group string
type Role string
type Resource string
type Requestor string
type Groups map[Group]struct{}

type Rule struct {
	Groups    Groups                `json:"groups"`
	Roles     map[Role]struct{}     `json:"roles"`
	Resources map[Resource]struct{} `json:"resources"`
}

type PolicyRules struct {
	PolicyRules []Rule `json:"policy_rules"`
}

// Returns deduplicated lists of groups, roles and resources
func (p *PolicyRules) ListOptions() (map[string]struct{}, map[string]struct{}, map[string]struct{}) {
	groups := make(map[string]struct{})
	roles := make(map[string]struct{})
	resources := make(map[string]struct{})
	for _, pol := range p.PolicyRules {
		for g := range pol.Groups {
			groups[string(g)] = struct{}{}
		}
		for rl := range pol.Roles {
			roles[string(rl)] = struct{}{}
		}
		for rsc := range pol.Resources {
			resources[string(rsc)] = struct{}{}
		}
	}
	return groups, roles, resources
}

type EscalationRequest struct {
	Requestor Requestor `json:"requestor"`
	Groups    Groups    `json:"groups"`
	Role      Role      `json:"role"`
	Resource  Resource  `json:"resource"`
	Reason    string    `json:"reason"`
	Timestamp string    `json:"timestamp"`
}

type EscalationApproval struct {
	*EscalationRequest
	Approver string   `json:"approver"`
	Status   Approval `json:"status"`
}

func (e EscalationApproval) String() string {
	return fmt.Sprintf("[AUDIT], Requestor: %s, Role: %s, Resource: %s, When: %s, Reason: %s, %s: %s", e.Requestor,
		e.Role, e.Resource, e.Timestamp, e.Reason, e.Status.String(), e.Approver)
}
