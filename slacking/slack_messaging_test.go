package slacking

import (
	"encoding/json"
	"testing"

	. "gcpsudobot/types"

	"github.com/google/go-cmp/cmp"
	"github.com/slack-go/slack"
)

var TestSlackPolicy = &PolicyRules{
	PolicyRules: []Rule{
		{
			Groups: map[Group]struct{}{
				"foo@gmail.com": {},
			},
			Roles: map[Role]struct{}{
				"roles/bar": {},
			},
			Resources: map[Resource]struct{}{
				"organizations/baz": {},
			},
		},
	},
}

// TODO: This is bit brittle, but ensures slack format isn't changing unneccesarily
func TestGenerateSlackEscalationRequestMessageFromModal(t *testing.T) {
	t.Run("GenerateSlackEscalationRequestMessageFromModal", func(t *testing.T) {
		blockString := `[{"type":"section","text":{"type":"mrkdwn","text":"There is a new authentication request to escalate GCP privileges"}},{"type":"section","fields":[{"type":"mrkdwn","text":"*User:*\ntest@example.io"},{"type":"mrkdwn","text":"*Role:*\norganizations/0000000000/roles/on_call_elevated"},{"type":"mrkdwn","text":"*Resource:*\norganizations/0000000000"},{"type":"mrkdwn","text":"*When:*\n100"},{"type":"mrkdwn","text":"*Reason:*\ntesting"}]},{"type":"actions","elements":[{"type":"button","text":{"type":"plain_text","text":"Approve"},"action_id":"apprv-id","value":"{\"requestor\":\"test@example.io\",\"groups\":{\"on-call@example.io\":{},\"testing@example.io\":{}},\"role\":\"organizations/0000000000/roles/on_call_elevated\",\"resource\":\"organizations/0000000000\",\"reason\":\"testing\",\"timestamp\":\"100\",\"approver\":\"default\",\"status\":true}","style":"danger"},{"type":"button","text":{"type":"plain_text","text":"Deny"},"action_id":"dny-id","value":"{\"requestor\":\"test@example.io\",\"groups\":{\"on-call@example.io\":{},\"testing@example.io\":{}},\"role\":\"organizations/0000000000/roles/on_call_elevated\",\"resource\":\"organizations/0000000000\",\"reason\":\"testing\",\"timestamp\":\"100\",\"approver\":\"default\",\"status\":false}"}]}]`
		r := &EscalationRequest{
			Requestor: "test@example.io",
			Groups:    map[Group]struct{}{"on-call@example.io": {}, "testing@example.io": {}},
			Role:      "organizations/0000000000/roles/on_call_elevated",
			Resource:  "organizations/0000000000",
			Reason:    "testing",
			Timestamp: "100",
		}
		got, err := GenerateSlackEscalationRequestMessageFromModal(r)
		if err != nil {
			t.Fatalf("handler failed: %v", err)
		}
		var blocks *slack.Blocks
		err = json.Unmarshal([]byte(blockString), &blocks)
		if err != nil {
			t.Fatalf("couldn't marshal to json: %s", err)
		}
		want := blocks.BlockSet
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %v", diff)
		}
	})
}

func TestGenerateSlackEscalationResponseMessage(t *testing.T) {
	tests := []struct {
		name     string
		input    *EscalationApproval
		expected []slack.Block
	}{
		{"Deny",
			&EscalationApproval{
				&EscalationRequest{
					Requestor: "test@example.io",
					Groups:    map[Group]struct{}{"on-call@example.io": struct{}{}},
					Role:      "organizations/0000000000/roles/on_call_elevated",
					Resource:  "organizations/0000000000",
					Reason:    "testing",
					Timestamp: "",
				},
				"test-approver@example.io",
				Denied,
			},
			[]slack.Block{
				&slack.SectionBlock{Type: "section", Text: &slack.TextBlockObject{Type: "mrkdwn", Text: "The Request has been denied."}},
				&slack.SectionBlock{
					Type:    "section",
					Text:    nil,
					BlockID: "",
					Fields: []*slack.TextBlockObject{
						{Type: "mrkdwn", Text: "*User:*\ntest@example.io"},
						{Type: "mrkdwn", Text: "*Role:*\norganizations/0000000000/roles/on_call_elevated"},
						{Type: "mrkdwn", Text: "*Resource:*\norganizations/0000000000"},
						{Type: "mrkdwn", Text: "*When:*\n"},
						{Type: "mrkdwn", Text: "*Reason:*\ntesting"},
						{Type: "mrkdwn", Text: "*Denier:*\ntest-approver@example.io"},
					},
					Accessory: nil,
				},
			},
		},
		{"Approve", &EscalationApproval{
			&EscalationRequest{
				Requestor: "test@example.io",
				Groups:    make(map[Group]struct{}),
				Role:      "organizations/0000000000/roles/on_call_elevated",
				Resource:  "organizations/0000000000",
				Reason:    "testing",
				Timestamp: "",
			},
			"test-approver@example.io",
			Approved,
		},
			[]slack.Block{
				&slack.SectionBlock{Type: "section", Text: &slack.TextBlockObject{Type: "mrkdwn", Text: "Approved. The role has been granted for 2 hours."}},
				&slack.SectionBlock{
					Type:    "section",
					Text:    nil,
					BlockID: "",
					Fields: []*slack.TextBlockObject{
						{Type: "mrkdwn", Text: "*User:*\ntest@example.io"},
						{Type: "mrkdwn", Text: "*Role:*\norganizations/0000000000/roles/on_call_elevated"},
						{Type: "mrkdwn", Text: "*Resource:*\norganizations/0000000000"},
						{Type: "mrkdwn", Text: "*When:*\n"},
						{Type: "mrkdwn", Text: "*Reason:*\ntesting"},
						{Type: "mrkdwn", Text: "*Approver:*\ntest-approver@example.io"},
					},
					Accessory: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateSlackEscalationResponseMessage(tt.input)
			if diff := cmp.Diff(got, tt.expected); diff != "" {
				t.Errorf("diff: %v", diff)
			}
		})
	}
}

func TestGenerateModal(t *testing.T) {
	t.Run("GenerateSlackEscalationRequestMessageFromModal", func(t *testing.T) {
		// This is using a single value for each category because https://github.com/golang/go/issues/27179
		want := `{
  "type": "modal",
  "title": {
    "type": "plain_text",
    "text": "IAM Escalation Request"
  },
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "plain_text",
        "text": "Please fill in the following info"
      }
    },
    {
      "type": "input",
      "block_id": "gcp_reason",
      "label": {
        "type": "plain_text",
        "text": "Reason"
      },
      "element": {
        "type": "plain_text_input",
        "action_id": "reasonz",
        "placeholder": {
          "type": "plain_text",
          "text": "Enter the reason for the request"
        }
      }
    },
    {
      "type": "input",
      "block_id": "gcp_role",
      "label": {
        "type": "plain_text",
        "text": "Role"
      },
      "element": {
        "type": "static_select",
        "action_id": "rolez",
        "options": [
          {
            "text": {
              "type": "plain_text",
              "text": "roles/bar"
            },
            "value": "roles/bar",
            "description": {
              "type": "plain_text",
              "text": "roles/bar"
            }
          }
        ]
      }
    },
    {
      "type": "input",
      "block_id": "gcp_resource",
      "label": {
        "type": "plain_text",
        "text": "Resource"
      },
      "element": {
        "type": "static_select",
        "action_id": "resourcez",
        "options": [
          {
            "text": {
              "type": "plain_text",
              "text": "organizations/baz"
            },
            "value": "organizations/baz",
            "description": {
              "type": "plain_text",
              "text": "organizations/baz"
            }
          }
        ]
      }
    }
  ],
  "close": {
    "type": "plain_text",
    "text": "Close"
  },
  "submit": {
    "type": "plain_text",
    "text": "Submit"
  }
}`
		g := GenerateModalRequest(TestSlackPolicy)
		got, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			t.Fatalf("couldn't marshal to json: %s", err)
		}
		if diff := cmp.Diff(string(got), want); diff != "" {
			t.Errorf("diff: %v", diff)
		}
	})
}
