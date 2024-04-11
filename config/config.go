package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"

	"os"

	. "github.com/seslattery/gcpsudobot/types"
)

type Config struct {
	ValidDomain            string
	GsuiteAdmin            string
	SlackChannel           string
	SlackSigningSecret     string
	SlackToken             string
	EscalationPolicy       *PolicyRules
	DurationOfGrantInHours int
	MockGoogleAPIs         bool
}

var Cfg *Config

func init() {
	var b bool
	var err error
	if os.Getenv("MOCK_GOOGLE_APIS") != "" {
		b, err = strconv.ParseBool(os.Getenv("MOCK_GOOGLE_APIS"))
		if err != nil {
			slog.Error(fmt.Sprintf("%s", err))
		}
	}

	// Setting defaults for some env vars because this config is used by tests
	var duration = 2
	if os.Getenv("DURATION_OF_GRANT") != "" {
		duration, err = strconv.Atoi(os.Getenv("DURATION_OF_GRANT"))
		if err != nil {
			slog.Error(fmt.Sprintf("%s", err))
		}
	}

	var validDomain = "gmail.com"
	if os.Getenv("VALID_DOMAIN") != "" {
		validDomain = os.Getenv("VALID_DOMAIN")
	}

	var gsuiteAdmin = "admin@gmail.com"
	if os.Getenv("GSUITE_ADMIN_ACCOUNT_TO_IMPERSONATE") != "" {
		gsuiteAdmin = os.Getenv("GSUITE_ADMIN_ACCOUNT_TO_IMPERSONATE")
	}

	var EscalationPolicy *PolicyRules
	if os.Getenv("POLICY_RULES") == "" {
		EscalationPolicy = TestEscalationPolicy
	} else {
		err = json.Unmarshal([]byte(os.Getenv("POLICY_RULES")), EscalationPolicy)
		if err != nil {
			slog.Error(fmt.Sprintf("config has invalid policy: %s", err))
		}
	}
	Cfg = &Config{
		ValidDomain:            validDomain,
		GsuiteAdmin:            gsuiteAdmin,
		SlackChannel:           os.Getenv("SLACK_CHANNEL"),
		MockGoogleAPIs:         b,
		SlackSigningSecret:     os.Getenv("SLACK_SECRET"),
		SlackToken:             os.Getenv("SLACK_API_TOKEN"),
		EscalationPolicy:       EscalationPolicy,
		DurationOfGrantInHours: duration,
	}
}

// Without a policy defined all requests will be denied by default.
// Policies can only allow access to roles and resources
// No support for hierarchy
// No support for individual membership
// No support for wildcards
var TestEscalationPolicy = &PolicyRules{
	PolicyRules: []Rule{
		{
			Groups: map[Group]struct{}{
				"on-call@gmail.com": struct{}{},
			},
			Roles: map[Role]struct{}{
				"organizations/0000000000/roles/on_call_elevated": struct{}{},
			},
			Resources: map[Resource]struct{}{
				"organizations/0000000000": struct{}{},
			},
		},
		{
			Groups: map[Group]struct{}{
				"on-call@gmail.com": struct{}{},
			},
			Roles: map[Role]struct{}{
				"organizations/0000000000/roles/on_call_elevated": struct{}{},
			},
			Resources: map[Resource]struct{}{
				"projects/testing": struct{}{},
			},
		},
		{
			Groups: map[Group]struct{}{
				"prod-db-access@gmail.com": struct{}{},
			},
			Roles: map[Role]struct{}{
				"roles/cloudsql.admin": struct{}{},
			},
			Resources: map[Resource]struct{}{
				"projects/testing": struct{}{},
			},
		},
		{
			Groups: map[Group]struct{}{
				"on-call-sudo@gmail.com": struct{}{},
			},
			Roles: map[Role]struct{}{
				"organizations/0000000000/roles/hub_root": struct{}{},
			},
			Resources: map[Resource]struct{}{
				"organizations/0000000000": struct{}{},
			},
		},
	},
}
