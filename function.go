package gcpsudobot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"gcpsudobot/authz"
	"gcpsudobot/config"
	"gcpsudobot/gcp"
	"gcpsudobot/slacking"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/slack-go/slack"
)

var slackClient *slack.Client
var googleService *gcp.Service

func init() {
	opts := &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))
	slog.SetDefault(logger)
	slackClient = slack.New(config.Cfg.SlackToken)
	// By mocking all of the calls to the google api's, we're able to develop this against the slack components much more easily
	if config.Cfg.MockGoogleAPIs {
		googleService = gcp.NewService(gcp.NewMockGoogler())
	} else {
		var err error
		googleService, err = gcp.NewGoogleService()
		if err != nil {
			slog.Error(fmt.Sprintf("%s", err))
			return

		}
	}
	// Ensure any exposed functions have verifyMessageFromSlack called as their first step
	functions.HTTP("SlashHandler", SlashHandler)
	functions.HTTP("ActionHandler", ActionHandler)
}

func SlashHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("SlashHandler")
	if err := verifyMessageFromSlack(r, config.Cfg.SlackSigningSecret); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s, err := slack.SlashCommandParse(r)
	if err != nil {
		slog.Error(fmt.Sprintf("%s", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch s.Command {
	case "/sudo":
		modalRequest := slacking.GenerateModalRequest(config.Cfg.EscalationPolicy)
		_, err = slackClient.OpenView(s.TriggerID, modalRequest)
		if err != nil {
			slog.Error(fmt.Sprintf("opening view: %s", err))
			w.WriteHeader(http.StatusInternalServerError)
		}
	default:
		slog.Error("unsupported slash command")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// This is what handles any slack interactions
func ActionHandler(w http.ResponseWriter, r *http.Request) {
	slog.Debug("ActionHandler")
	if err := verifyMessageFromSlack(r, config.Cfg.SlackSigningSecret); err != nil {
		slog.Error(err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var message slack.InteractionCallback
	err := json.Unmarshal([]byte(r.FormValue("payload")), &message)
	if err != nil {
		slog.Error(fmt.Sprintf("invalid action response json: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch message.Type {
	case "view_submission":
		//send an empty acceptance response
		w.WriteHeader(http.StatusOK)
		err = modalSubmissionController(message, slackClient, googleService)
		if err != nil {
			if errors.Is(err, ErrUnauthorized) {
				modalError(err)
			}
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	case "block_actions":
		msg, err := approvalActionController(message)
		if err != nil {
			slog.Error(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sendHTTPResponse(w, r, message.ResponseURL, msg)
	default:
		slog.Error(fmt.Sprintf("unsupported action: %v", message.Type))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// verifyMessageFromSlack is what ensures the messages are coming from slack by utilizing a unique signing secret.
func verifyMessageFromSlack(r *http.Request, signingSecret string) error {
	slog.Debug("verifying message came from slack")

	// Read request body
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("invalid request body: %v", err)
	}
	slog.Debug(fmt.Sprintf("header: %v", r.Header))
	// Reset request body for other methods to act on
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	// Verify signing secret
	verifier, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	if _, err := verifier.Write(body); err != nil {
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	if err := verifier.Ensure(); err != nil {
		return fmt.Errorf("failed to verify SigningSecret: %v", err)
	}
	return nil
}

func approvalActionController(message slack.InteractionCallback) ([]byte, error) {
	ctx := context.Background()
	escalationApproval, err := slacking.ParseEscalationRequestFromApproval(slackClient, message)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse escalation request from approval: %v", err)
	}
	if err := authz.AuthorizeApprovalAndGrantIAM(ctx, config.Cfg.EscalationPolicy, escalationApproval, googleService); err != nil {
		return nil, fmt.Errorf("couldn't grant iam: %v", err)
	}
	blocks := slacking.GenerateSlackEscalationResponseMessage(escalationApproval)
	msg := slack.NewBlockMessage(blocks...)
	msg.ResponseType = "in_channel"
	msg.ReplaceOriginal = true
	b, err := json.MarshalIndent(msg, "", "    ")
	if err != nil {
		return nil, fmt.Errorf("marshalling json: %v", err)
	}
	return b, nil
}

var ErrUnauthorized = errors.New("unauthorized - please double check it's a valid role and resource combination")

func modalSubmissionController(message slack.InteractionCallback, slackClient *slack.Client, googleService *gcp.Service) error {
	slog.Info("modal submission")
	ctx := context.Background()
	escalationRequest, err := slacking.ParseEscalationRequestFromModal(slackClient, message)
	if err != nil {
		return fmt.Errorf("couldn't parse slack modal: %v", err)
	}
	approval, err := authz.AuthorizeRequest(ctx, config.Cfg.EscalationPolicy, escalationRequest, googleService)
	if err != nil {
		return fmt.Errorf("couldn't grant iam: %v", err)
	}
	if !approval {
		return ErrUnauthorized
	}

	blocks, err := slacking.GenerateSlackEscalationRequestMessageFromModal(escalationRequest)
	if err != nil {
		return fmt.Errorf("couldn't generate modal slack response: %v", err)

	}
	msg := slack.MsgOptionBlocks(blocks...)
	_, _, err = slackClient.PostMessage(config.Cfg.SlackChannel, msg)
	if err != nil {
		return fmt.Errorf("can't complete modal action: %v", err)
	}
	return nil
}

func sendHTTPResponse(w http.ResponseWriter, r *http.Request, responseURL string, b []byte) {
	req, err := http.NewRequestWithContext(r.Context(), "POST", responseURL, bytes.NewReader(b))
	if err != nil {
		slog.Error(fmt.Sprintf("generating http request: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Error(fmt.Sprintf("sending http request: %v", err))
		w.WriteHeader(http.StatusInternalServerError)
	}
	defer resp.Body.Close()
}

func modalError(err error) {
	errMessage := fmt.Sprintf("couldn't handle escalation request: %v", err)
	slog.Error(errMessage)
	blocks := slacking.TextToBlock(errMessage)
	msg := slack.MsgOptionBlocks(blocks...)
	if _, _, err := slackClient.PostMessage(config.Cfg.SlackChannel, msg); err != nil {
		slog.Error(fmt.Sprintf("can't complete modal action: %v", err))
	}
}
