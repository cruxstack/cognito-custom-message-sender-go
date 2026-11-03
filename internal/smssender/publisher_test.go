package smssender

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
)

type fakeSNS struct {
	inputs []*sns.PublishInput
	err    error
}

func (f *fakeSNS) Publish(_ context.Context, in *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &sns.PublishOutput{MessageId: aws.String("msg-1")}, nil
}

func TestMessageAttributes(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want map[string]string
	}{
		{"defaults to transactional", Message{}, map[string]string{attrSMSType: "Transactional"}},
		{"promotional", Message{MessageType: "Promotional"}, map[string]string{attrSMSType: "Promotional"}},
		{
			"sender id and short code",
			Message{SenderID: "EXAMPLE", ShortCode: "12345"},
			map[string]string{attrSMSType: "Transactional", attrSenderID: "EXAMPLE", attrOriginationNumber: "12345"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MessageAttributes(tc.msg)
			if len(got) != len(tc.want) {
				t.Fatalf("attributes = %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if aws.ToString(got[k].StringValue) != v || aws.ToString(got[k].DataType) != "String" {
					t.Errorf("%s = %+v, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestSNSPublisher(t *testing.T) {
	f := &fakeSNS{}
	p := &SNSPublisher{Client: f}

	if err := p.Publish(context.Background(), Message{PhoneNumber: "+12065550100", Body: "Your code is: 123456"}); err != nil {
		t.Fatal(err)
	}
	in := f.inputs[0]
	if aws.ToString(in.PhoneNumber) != "+12065550100" || aws.ToString(in.Message) != "Your code is: 123456" {
		t.Errorf("input = %+v", in)
	}

	f.err = errors.New("throttled")
	if err := p.Publish(context.Background(), Message{PhoneNumber: "+12065550100"}); err == nil {
		t.Error("Publish() should return the sns error")
	}
}

func TestSNSPublisher_DryRun(t *testing.T) {
	f := &fakeSNS{}
	if err := (&SNSPublisher{Client: f, DryRun: true}).Publish(context.Background(), Message{PhoneNumber: "+12065550100"}); err != nil {
		t.Fatal(err)
	}
	if len(f.inputs) != 0 {
		t.Error("dry run should not call sns")
	}
}
