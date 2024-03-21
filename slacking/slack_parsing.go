package slacking

import (
	"encoding/json"
	"fmt"
	"time"

	. "gcpsudobot/types"

	"github.com/slack-go/slack"
)

func ParseEscalationRequestFromApproval(api *slack.Client, message slack.InteractionCallback) (*EscalationApproval, error) {
	var r *EscalationApproval
	if err := json.Unmarshal([]byte(message.ActionCallback.BlockActions[0].Value), &r); err != nil {
		return nil, fmt.Errorf("can't unmarshal block action: %v", err)
	}
	approverProfile, err := api.GetUserProfile(&slack.GetUserProfileParameters{
		UserID:        message.User.ID,
		IncludeLabels: true,
	})
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}
	r.Approver = approverProfile.Email
	return r, nil
}

func ParseEscalationRequestFromModal(api *slack.Client, message slack.InteractionCallback) (*EscalationRequest, error) {
	profile, err := api.GetUserProfile(&slack.GetUserProfileParameters{
		UserID:        message.User.ID,
		IncludeLabels: true,
	})
	if err != nil {
		return nil, fmt.Errorf("can't get user info from slack: %v", err)
	}
	requestor := Requestor(profile.Email)
	reason := message.View.State.Values[ReasonBlockID][ReasonActionID].Value
	role := Role(message.View.State.Values[RoleBlockID][RoleActionID].SelectedOption.Value)
	resource := Resource(message.View.State.Values[ResourceBlockID][ResourceActionID].SelectedOption.Value)

	r := &EscalationRequest{
		Requestor: requestor,
		Groups:    make(map[Group]struct{}),
		Role:      role,
		Resource:  resource,
		Reason:    reason,
		Timestamp: time.Now().Format(time.RFC822),
	}
	return r, nil
}
