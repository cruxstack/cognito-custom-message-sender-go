package sms

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	historyIndexPhoneNumber = "userPhoneNumber-index"
	isoMillisLayout         = "2006-01-02T15:04:05.000Z07:00"
)

// Record is one SMS attempt.
type Record struct {
	Trigger                string
	UserID                 string
	UserEmailAddress       string
	UserPhoneNumber        string
	UserPhoneNumberCountry string
	SentAt                 time.Time
}

// HistoryStore records SMS attempts and counts recent attempts per phone
// number.
type HistoryStore interface {
	Save(ctx context.Context, r Record, expiresAt time.Time) error
	CountByPhoneNumber(ctx context.Context, phoneNumber string, since time.Time) (int, error)
}

// DynamoDBAPI is the subset of the dynamodb client used by DynamoDBHistory.
type DynamoDBAPI interface {
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	Query(ctx context.Context, params *dynamodb.QueryInput, optFns ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error)
}

// DynamoDBHistory uses the table layout of the earlier node.js sender: hash
// key historyId, range key sentAtEpoch (epoch millis), and a
// userPhoneNumber-index global secondary index on userPhoneNumber and
// sentAtEpoch. The ttl attribute holds epoch seconds.
type DynamoDBHistory struct {
	client DynamoDBAPI
	table  string
}

func NewDynamoDBHistory(client DynamoDBAPI, table string) *DynamoDBHistory {
	return &DynamoDBHistory{client: client, table: table}
}

func (h *DynamoDBHistory) Save(ctx context.Context, r Record, expiresAt time.Time) error {
	sentAt := r.SentAt.UTC()
	item := map[string]ddbtypes.AttributeValue{
		"historyId":              str(fmt.Sprintf("sms-%s-%d", r.UserID, sentAt.UnixMilli())),
		"type":                   str("sms"),
		"trigger":                str(r.Trigger),
		"userEmailAddress":       str(r.UserEmailAddress),
		"userPhoneNumber":        str(r.UserPhoneNumber),
		"userPhoneNumberCountry": str(r.UserPhoneNumberCountry),
		"sentAt":                 str(sentAt.Format(isoMillisLayout)),
		"sentAtEpoch":            num(sentAt.UnixMilli()),
		"ttl":                    num(expiresAt.Unix()),
	}
	// userId is a secondary index key, which can't be an empty string
	if r.UserID != "" {
		item["userId"] = str(r.UserID)
	}

	if _, err := h.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(h.table), Item: item}); err != nil {
		return fmt.Errorf("dynamodb put item: %w", err)
	}
	return nil
}

func (h *DynamoDBHistory) CountByPhoneNumber(ctx context.Context, phoneNumber string, since time.Time) (int, error) {
	out, err := h.client.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(h.table),
		IndexName:              aws.String(historyIndexPhoneNumber),
		KeyConditionExpression: aws.String("userPhoneNumber = :userPhoneNumber AND sentAtEpoch >= :sentAtEpoch"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":userPhoneNumber": str(phoneNumber),
			":sentAtEpoch":     num(since.UnixMilli()),
		},
		Select: ddbtypes.SelectCount,
	})
	if err != nil {
		return 0, fmt.Errorf("dynamodb query: %w", err)
	}
	return int(out.Count), nil
}

func str(s string) *ddbtypes.AttributeValueMemberS {
	return &ddbtypes.AttributeValueMemberS{Value: s}
}

func num(n int64) *ddbtypes.AttributeValueMemberN {
	return &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(n, 10)}
}

// MemoryHistory is an in-process HistoryStore for tests and local debugging.
type MemoryHistory struct {
	mu      sync.Mutex
	records []Record
}

func NewMemoryHistory() *MemoryHistory {
	return &MemoryHistory{}
}

func (h *MemoryHistory) Save(_ context.Context, r Record, _ time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *MemoryHistory) CountByPhoneNumber(_ context.Context, phoneNumber string, since time.Time) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if r.UserPhoneNumber == phoneNumber && !r.SentAt.Before(since) {
			n++
		}
	}
	return n, nil
}

// Records returns the saved records.
func (h *MemoryHistory) Records() []Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Record(nil), h.records...)
}
