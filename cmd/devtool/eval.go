package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/cognito"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/email"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/policy"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/sms"
	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/verify"
)

// evalResult is printed for each event.
type evalResult struct {
	Index    int    `json:"index"`
	Trigger  string `json:"trigger"`
	Input    any    `json:"input,omitempty"`
	Decision any    `json:"decision,omitempty"`
	// Outcome summarizes what the sender would do.
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

func evalCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	eventsPath := fs.String("events", "", "JSON file with an event or an array of events (required)")
	emailPolicy := fs.String("email-policy", "", "email policy (required for email events)")
	smsPolicy := fs.String("sms-policy", "", "SMS policy (required for SMS events)")
	verifyEmail := fs.Bool("verify", true, "add an offline email verification result to the email policy input")
	attempts := fs.Int("sms-attempts", 1, "value for input.history.recentAttempts in SMS policy input")
	showInput := fs.Bool("show-input", false, "print the policy input for each event")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *eventsPath == "" {
		fs.Usage()
		return errors.New("-events is required")
	}

	slog.SetDefault(newLogger(io.Discard, slog.LevelError))

	events, err := readEvents(*eventsPath)
	if err != nil {
		return err
	}

	var emailEngine, smsEngine *policy.Engine
	if *emailPolicy != "" {
		if emailEngine, err = policy.Load(ctx, *emailPolicy, email.PolicyQuery); err != nil {
			return err
		}
	}
	if *smsPolicy != "" {
		if smsEngine, err = policy.Load(ctx, *smsPolicy, sms.PolicyQuery, policy.AllowRegoV0()); err != nil {
			return err
		}
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	failed := 0
	for i, raw := range events {
		var e cognito.Event
		res := evalResult{Index: i}
		if err := json.Unmarshal(raw, &e); err != nil {
			res.Error = fmt.Sprintf("decode event: %v", err)
		} else {
			res.Trigger = e.TriggerSource
			evalEvent(ctx, &e, &res, emailEngine, smsEngine, *verifyEmail, *attempts)
		}
		if !*showInput {
			res.Input = nil
		}
		if res.Error != "" {
			res.Outcome, failed = "error", failed+1
		}
		if err := enc.Encode(res); err != nil {
			return err
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d events failed", failed, len(events))
	}
	return nil
}

func evalEvent(ctx context.Context, e *cognito.Event, res *evalResult, emailEngine, smsEngine *policy.Engine, verifyEmail bool, attempts int) {
	switch e.Kind() {
	case cognito.KindEmail:
		if emailEngine == nil {
			res.Error = "email event but no -email-policy"
			return
		}
		var v *verify.Result
		if to := e.Attribute("email"); verifyEmail && to != "" {
			v, _ = verify.Offline{}.Verify(ctx, to)
		}
		in := email.NewPolicyInput(e, v, nil)
		res.Input = in

		d, err := policy.Eval[email.Decision](ctx, emailEngine, in)
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Decision = d

		msg, err := d.Message(e.Attribute("email"))
		switch {
		case err != nil:
			res.Error = err.Error()
		case msg == nil:
			res.Outcome = "denied"
		default:
			res.Outcome = "send"
		}

	case cognito.KindSMS:
		if smsEngine == nil {
			res.Error = "sms event but no -sms-policy"
			return
		}
		phone, err := sms.ParsePhoneNumber(e.Attribute("phone_number"))
		if err != nil {
			res.Outcome = "dropped: invalid phone number"
			return
		}
		in := sms.NewPolicyInput(e, phone, &sms.PolicyHistory{RecentAttempts: attempts}, nil)
		res.Input = in

		d, err := policy.Eval[sms.Decision](ctx, smsEngine, in)
		if err != nil {
			res.Error = err.Error()
			return
		}
		res.Decision = d

		action, err := policy.ParseAction(d.Action)
		switch {
		case err != nil:
			res.Error = err.Error()
		case action == policy.ActionDeny:
			res.Outcome = "denied"
		case d.Allow.Message == "":
			res.Error = `"allow.message" is required`
		default:
			res.Outcome = "send"
		}

	default:
		res.Outcome = "ignored: unsupported trigger"
	}
}
