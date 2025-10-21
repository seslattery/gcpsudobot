# CLAUDE.md - GCPSUDOBOT

## Quick Overview

GCPSUDOBOT is a Slack bot for time-limited, conditional IAM permission escalation in Google Cloud Platform (GCP). It enables engineers to request temporary elevated GCP permissions through Slack with a mandatory approval workflow.

**Core Workflow:**
1. User runs `/sudo` command in Slack
2. Modal prompts for Role, Resource, and Reason
3. Bot validates user's Google Group membership against policy
4. Request posted to approval channel
5. Another user approves/denies the request
6. If approved, conditional IAM role granted for 2 hours (configurable)

**Technology Stack:**
- Language: Go 1.21+
- Deployment: Google Cloud Functions (serverless)
- Integration: Slack API, GCP IAM, Google Workspace Admin API

## Architecture

### Entry Points (function.go)

**Cloud Functions Handlers:**
- `SlashHandler` (function.go:50) - Processes `/sudo` command, opens Slack modal
- `ActionHandler` (function.go:79) - Handles modal submissions and approval button clicks

Both handlers verify requests using Slack signing secret via `verifyMessageFromSlack` (function.go:122).

### Core Components

```
gcpsudobot/
├── function.go          # Entry point: SlashHandler, ActionHandler
├── types/               # Data structures (EscalationRequest, PolicyRules, etc.)
├── authz/               # Authorization logic (group membership, policy validation)
├── gcp/                 # GCP integration (IAM policies, Google Groups API)
├── slacking/            # Slack UI (modals, messages, button parsing)
├── config/              # Environment variable configuration
└── cmd/                 # Local development HTTP server
```

### Key Types (types/types.go)

```go
type EscalationRequest struct {
    Requestor Requestor  // User requesting access
    Groups    Groups     // User's Google Groups
    Role      Role       // IAM role requested
    Resource  Resource   // GCP resource (project/org)
    Reason    string     // Justification
    Timestamp string
}

type EscalationApproval struct {
    *EscalationRequest
    Approver string
    Status   Approval   // Approved or Denied
}

type Rule struct {
    Groups    Groups                // Allowed Google Groups
    Roles     map[Role]struct{}     // Allowed IAM roles
    Resources map[Resource]struct{} // Allowed resources
}

type PolicyRules struct {
    PolicyRules []Rule  // List of authorization rules
}
```

### Request Flow

**1. Modal Submission (function.go:170)**
```
modalSubmissionController
  → slacking.ParseEscalationRequestFromModal
  → authz.AuthorizeRequest  (validates against policy)
  → slacking.GenerateSlackEscalationRequestMessageFromModal
  → slackClient.PostMessage (posts to approval channel)
```

**2. Approval Action (function.go:148)**
```
approvalActionController
  → slacking.ParseEscalationRequestFromApproval
  → authz.AuthorizeApprovalAndGrantIAM  (re-validates + grants IAM)
  → gcp.BindIAMPolicy  (creates conditional IAM binding)
  → slacking.GenerateSlackEscalationResponseMessage
  → Update message with approval/denial status
```

## Critical Files

| File | Lines | Purpose |
|------|-------|---------|
| `function.go` | 222 | Main entry point, request routing |
| `authz/authz.go` | 75 | Authorization checks (CRITICAL for security) |
| `gcp/gcp.go` | 248 | IAM policy manipulation (HANDLE WITH CARE) |
| `config/config.go` | 136 | Configuration, environment variables |
| `slacking/slack_messages.go` | 171 | Slack UI components |
| `types/types.go` | 81 | Core data structures |

## Configuration

### Required Environment Variables

```bash
SLACK_API_TOKEN="xoxb-..."              # Slack bot token
SLACK_SECRET="..."                       # Slack signing secret
SLACK_CHANNEL="C123ABC456"               # Approval channel ID
VALID_DOMAIN="example.com"               # Email domain restriction
GSUITE_ADMIN_ACCOUNT_TO_IMPERSONATE="admin@example.com"  # Google Workspace admin
GCP_SERVICE_ACCOUNT="bot@project.iam.gserviceaccount.com"  # Service account
POLICY_RULES='{"policy_rules":[...]}'    # JSON policy definition
DURATION_OF_GRANT="2"                    # Hours (default: 2)
MOCK_GOOGLE_APIS="false"                 # Mock GCP APIs for testing
```

### Policy Rules Format

PolicyRules define what role/resource combinations are allowed for which groups. **No wildcards, no hierarchy support.**

```json
{
  "policy_rules": [
    {
      "groups": {
        "on-call@example.com": {}
      },
      "roles": {
        "organizations/123456/roles/on_call_elevated": {}
      },
      "resources": {
        "projects/my-project": {}
      }
    }
  ]
}
```

**Authorization Logic:**
- User must be in a Google Group listed in a rule
- Role and Resource must both be in the same rule as that group
- First matching rule wins
- Default deny if no match

## Security Considerations

### CRITICAL Security Features

1. **Request Verification** (function.go:122)
   - All requests verified using Slack signing secret
   - Prevents unauthorized access to unauthenticated Cloud Function

2. **Double Authorization Check**
   - Authorization at request time (function.go:177)
   - Re-authorization at approval time (function.go:154)
   - Prevents malicious approval messages from granting access

3. **Self-Approval Prevention**
   - Requestor cannot approve their own requests
   - Enforced in authorization logic

4. **Domain Validation**
   - `VALID_DOMAIN` restricts users by email domain
   - Prevents external users from using the bot

5. **Minimal Scopes**
   - Google Workspace delegation: `admin.directory.group.readonly` only
   - Service account should have minimal IAM permissions

6. **Conditional IAM Grants**
   - Uses GCP IAM Conditions with time-based expiry
   - Bindings expire automatically after configured duration

### WARNING: Sensitive Areas

**gcp/gcp.go** - IAM policy manipulation
- `BindIAMPolicy` (gcp/gcp.go) - Modifies IAM policies, bugs could delete policies
- Always test IAM changes with `MOCK_GOOGLE_APIS=true` first
- Production service account needs `roles/resourcemanager.projectIamAdmin`

**authz/authz.go** - Authorization logic
- Bugs here could allow unauthorized access
- Policy enforcement is the primary security control

## Development

### Local Development Setup

1. Create test Slack workspace
2. Install app using `SLACK_APP_MANIFEST_DEV.yml`
3. Setup ngrok tunnel: `ngrok http --domain=<YOUR_DOMAIN> 8080`
4. Configure Slack app URLs to ngrok domain
5. Run locally with mocked Google APIs:

```bash
SLACK_API_TOKEN="xoxb-..." \
SLACK_SECRET="..." \
SLACK_CHANNEL="C123..." \
MOCK_GOOGLE_APIS="true" \
go run cmd/main.go
```

### Testing

```bash
# Run all tests with coverage
go test -cover -v ./...

# Run vulnerability scan
govulncheck ./...
```

Tests use mock implementations:
- `gcp_mock.go` - Mock Google Groups and IAM API
- `config/config.go` - TestEscalationPolicy for testing

### CI/CD

GitHub Actions (.github/workflows/go.yml):
- Runs on every push
- Executes `go test -cover -v ./...`
- Runs `govulncheck` for vulnerability scanning

## Known Issues & Limitations

1. **No cleanup of expired grants** - Conditional IAM bindings accumulate, may fail at 50+ grants per user
2. **No TTL management** - Expired bindings remain in policy (not deleted)
3. **No folder support** - Only projects and organizations
4. **No wildcards** - Every role/resource combo needs explicit rule
5. **No hierarchical rules** - Can't grant org-level access that cascades

## Important Gotchas

### Service Account Permissions

The Cloud Function's service account needs:
- `roles/resourcemanager.projectIamAdmin` (for project-level grants)
- OR these org-level permissions:
  ```
  resourcemanager.organizations.get
  resourcemanager.organizations.getIamPolicy
  resourcemanager.organizations.setIamPolicy
  ```

### Domain-Wide Delegation

Service account must have domain-wide delegation configured with scope:
```
https://www.googleapis.com/auth/admin.directory.group.readonly
```

This allows impersonating `GSUITE_ADMIN_ACCOUNT_TO_IMPERSONATE` to look up group membership.

### Policy Configuration

- Store `POLICY_RULES` in version control
- Use CODEOWNERS to require multiple reviewers
- Review policy changes carefully - they grant broad access

### IAM Condition Format

The bot creates time-based conditions like:
```
request.time < timestamp("2024-03-21T13:21:52Z")
```

These expire automatically but bindings remain in the policy.

## Making Changes

### Adding New Features

1. **Never skip security checks** - All code paths must verify authorization
2. **Test with mocks first** - Use `MOCK_GOOGLE_APIS=true`
3. **Add tests** - Maintain test coverage
4. **Update documentation** - Keep README.md in sync

### Common Tasks

**Adding a new slash command:**
- Update `SlashHandler` in function.go:63
- Add case statement for new command
- Register in Slack app manifest

**Modifying authorization:**
- Edit `authz/authz.go` with extreme care
- Add comprehensive tests
- Consider security implications

**Changing Slack UI:**
- Modify `slacking/slack_messages.go`
- Update parsing in `slacking/slack_parsing.go`
- Test with actual Slack workspace

## Deployment

Deploy to Google Cloud Functions:

```bash
gcloud functions deploy gcpsudobot \
  --runtime go121 \
  --trigger-http \
  --allow-unauthenticated \
  --service-account=<SERVICE_ACCOUNT> \
  --set-env-vars="SLACK_API_TOKEN=...,SLACK_SECRET=...,..."
```

**Note:** Function is unauthenticated, security enforced via Slack signing secret verification.

## Contributing

See README.md for contribution guidelines. Key points:
- Open PRs for review
- Add tests for new functionality
- Run `go test` and `govulncheck` before submitting
- Be extra cautious with authorization and IAM code

## References

- README.md - Comprehensive user documentation
- Google Cloud Functions: https://cloud.google.com/functions
- Slack API: https://api.slack.com/
- GCP IAM Conditions: https://cloud.google.com/iam/docs/conditions-overview
- Domain-Wide Delegation: https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority
