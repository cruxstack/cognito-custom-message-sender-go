package smssender

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"
)

const (
	attrSMSType           = "AWS.SNS.SMS.SMSType"
	attrSenderID          = "AWS.SNS.SMS.SenderID"
	attrOriginationNumber = "AWS.MM.SMS.OriginationNumber"

	defaultMessageType = "Transactional"
)

// Message is one SMS to publish.
type Message struct {
	PhoneNumber string
	Body        string
	MessageType string
	SenderID    string
	ShortCode   string
}

type Publisher interface {
	Publish(ctx context.Context, m Message) error
}

// SNSAPI is the subset of the sns client used by SNSPublisher.
type SNSAPI interface {
	Publish(ctx context.Context, params *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// SNSPublisher sends SMS with sns:Publish. In dry-run mode it logs instead of
// sending.
type SNSPublisher struct {
	Client SNSAPI
	DryRun bool
}

func (p *SNSPublisher) Publish(ctx context.Context, m Message) error {
	input := &sns.PublishInput{
		PhoneNumber:       aws.String(m.PhoneNumber),
		Message:           aws.String(m.Body),
		MessageAttributes: MessageAttributes(m),
	}

	if p.DryRun {
		slog.DebugContext(ctx, "dry-run sns sms send",
			"phone_masked", MaskPhoneNumber(m.PhoneNumber),
			"message_type", cmp.Or(m.MessageType, defaultMessageType),
			"sender_id", m.SenderID,
			"short_code", m.ShortCode,
		)
		return nil
	}

	out, err := p.Client.Publish(ctx, input)
	if err != nil {
		return fmt.Errorf("error publishing sms: %w", err)
	}

	slog.InfoContext(ctx, "sms sent", "message_id", aws.ToString(out.MessageId), "phone_masked", MaskPhoneNumber(m.PhoneNumber))
	return nil
}

// MessageAttributes returns the sns sms attributes for a message. The sender
// ID and origination number are set only when provided.
func MessageAttributes(m Message) map[string]snstypes.MessageAttributeValue {
	attrs := map[string]snstypes.MessageAttributeValue{
		attrSMSType: stringAttr(cmp.Or(m.MessageType, defaultMessageType)),
	}
	if m.ShortCode != "" {
		attrs[attrOriginationNumber] = stringAttr(m.ShortCode)
	}
	if m.SenderID != "" {
		attrs[attrSenderID] = stringAttr(m.SenderID)
	}
	return attrs
}

func stringAttr(v string) snstypes.MessageAttributeValue {
	return snstypes.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(v)}
}
