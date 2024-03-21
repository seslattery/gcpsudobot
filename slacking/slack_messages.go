package slacking

import (
	"encoding/json"
	"fmt"

	"gcpsudobot/config"
	. "gcpsudobot/types"

	"github.com/slack-go/slack"
)

const (
	ApprovalButtonID = "apprv-id"
	DenialButtonID   = "dny-id"
	ResourceActionID = "resourcez"
	RoleActionID     = "rolez"
	ReasonActionID   = "reasonz"
	ResourceBlockID  = "gcp_resource"
	RoleBlockID      = "gcp_role"
	ReasonBlockID    = "gcp_reason"
)

// slash command goes to function handler

func GenerateModalRequest(p *PolicyRules) slack.ModalViewRequest {
	_, roles, resources := p.ListOptions()
	roleOpts := createOptionBlockObjects(roles)
	resourceOpts := createOptionBlockObjects(resources)

	return slack.ModalViewRequest{
		Type:   slack.ViewType("modal"),
		Title:  &slack.TextBlockObject{Type: slack.PlainTextType, Text: "IAM Escalation Request"},
		Close:  &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Close"},
		Submit: &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Submit"},
		Blocks: slack.Blocks{
			BlockSet: []slack.Block{
				&slack.SectionBlock{
					Type: slack.MBTSection,
					Text: &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Please fill in the following info"},
				},
				&slack.InputBlock{
					Type:    slack.MBTInput,
					BlockID: ReasonBlockID,
					Label:   &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Reason"},
					Element: &slack.PlainTextInputBlockElement{
						Type:        slack.METPlainTextInput,
						ActionID:    ReasonActionID,
						Placeholder: &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Enter the reason for the request"},
					},
				},
				&slack.InputBlock{
					Type:    slack.MBTInput,
					BlockID: RoleBlockID,
					Label:   &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Role"},
					Element: &slack.SelectBlockElement{
						Type:     slack.OptTypeStatic,
						ActionID: RoleActionID,
						Options:  roleOpts,
					},
				},
				&slack.InputBlock{
					Type:    slack.MBTInput,
					BlockID: ResourceBlockID,
					Label:   &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Resource"},
					Element: &slack.SelectBlockElement{
						Type:     slack.OptTypeStatic,
						ActionID: ResourceActionID,
						Options:  resourceOpts,
					},
				},
			},
		},
	}
}

func GenerateSlackEscalationRequestMessageFromModal(r *EscalationRequest) ([]slack.Block, error) {
	// TODO: better default values / This is where the shift from a EscalationRequest to an EscalationApproval happens
	a := &EscalationApproval{
		r,
		"default",
		Denied,
	}
	// Approve and Deny Buttons
	denialPayload, err := json.Marshal(&a)
	if err != nil {
		return nil, fmt.Errorf("can't marshal json: %v", err)
	}
	denyBtn := &slack.ButtonBlockElement{
		Type:     slack.METButton,
		ActionID: DenialButtonID,
		Value:    string(denialPayload),
		Text:     &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Deny"},
	}

	a.Status = Approved
	approvalPayload, err := json.Marshal(&a)
	if err != nil {
		return nil, fmt.Errorf("can't marshal json: %v", err)
	}

	approveBtn := &slack.ButtonBlockElement{
		Type:     slack.METButton,
		ActionID: ApprovalButtonID,
		Value:    string(approvalPayload),
		Text:     &slack.TextBlockObject{Type: slack.PlainTextType, Text: "Approve"},
	}
	approveBtn.WithStyle("danger")
	actionBlock := slack.NewActionBlock("", approveBtn, denyBtn)

	return []slack.Block{
		&slack.SectionBlock{
			Type: slack.MBTSection,
			Text: &slack.TextBlockObject{Type: slack.MarkdownType, Text: "There is a new authentication request to escalate GCP privileges"},
		},
		&slack.SectionBlock{
			Type: slack.MBTSection,
			Fields: []*slack.TextBlockObject{
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*User:*\n%s", r.Requestor)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Role:*\n%s", r.Role)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Resource:*\n%s", r.Resource)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*When:*\n%s", r.Timestamp)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Reason:*\n%s", r.Reason)},
			},
			Accessory: nil,
		},
		actionBlock,
	}, nil
}

func GenerateSlackEscalationResponseMessage(r *EscalationApproval) []slack.Block {
	return []slack.Block{
		&slack.SectionBlock{
			Type: slack.MBTSection,
			Text: &slack.TextBlockObject{Type: slack.MarkdownType, Text: r.Status.ApprovalText(config.Cfg.DurationOfGrantInHours)},
		},
		&slack.SectionBlock{
			Type: slack.MBTSection,
			Fields: []*slack.TextBlockObject{
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*User:*\n%s", r.Requestor)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Role:*\n%s", r.Role)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Resource:*\n%s", r.Resource)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*When:*\n%s", r.Timestamp)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*Reason:*\n%s", r.Reason)},
				{Type: slack.MarkdownType, Text: fmt.Sprintf("*%s:*\n%s", r.Status.String(), r.Approver)},
			},
			Accessory: nil,
		},
	}
}

func TextToBlock(text string) []slack.Block {
	var headerSection *slack.SectionBlock

	headerText := slack.NewTextBlockObject(slack.MarkdownType, text, false, false)
	headerSection = slack.NewSectionBlock(headerText, nil, nil)
	blocks := []slack.Block{
		headerSection,
	}
	return blocks
}

func createOptionBlockObjects(options map[string]struct{}) []*slack.OptionBlockObject {
	optionBlockObjects := make([]*slack.OptionBlockObject, 0, len(options))
	for o := range options {
		optionText := slack.NewTextBlockObject(slack.PlainTextType, o, false, false)
		descriptionText := slack.NewTextBlockObject(slack.PlainTextType, o, false, false)
		optionBlockObjects = append(optionBlockObjects, slack.NewOptionBlockObject(o, optionText, descriptionText))
	}
	return optionBlockObjects
}
