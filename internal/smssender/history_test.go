package smssender

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

var testNow = time.Date(2026, 1, 2, 3, 4, 5, 678_000_000, time.UTC)

type fakeDynamoDB struct {
	putInput   *dynamodb.PutItemInput
	queryInput *dynamodb.QueryInput
	count      int32
	err        error
}

func (f *fakeDynamoDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.putInput = in
	return &dynamodb.PutItemOutput{}, f.err
}

func (f *fakeDynamoDB) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	f.queryInput = in
	if f.err != nil {
		return nil, f.err
	}
	return &dynamodb.QueryOutput{Count: f.count}, nil
}

func attrS(item map[string]ddbtypes.AttributeValue, k string) string {
	if v, ok := item[k].(*ddbtypes.AttributeValueMemberS); ok {
		return v.Value
	}
	return "<missing>"
}

func attrN(item map[string]ddbtypes.AttributeValue, k string) string {
	if v, ok := item[k].(*ddbtypes.AttributeValueMemberN); ok {
		return v.Value
	}
	return "<missing>"
}

func TestDynamoDBHistory_Save(t *testing.T) {
	f := &fakeDynamoDB{}
	h := NewDynamoDBHistory(f, "history")

	err := h.Save(context.Background(), Record{
		Trigger:                "CustomSMSSender_SignUp",
		UserID:                 "abc123",
		UserEmailAddress:       "user@example.com",
		UserPhoneNumber:        "+12065550100",
		UserPhoneNumberCountry: "US",
		SentAt:                 testNow,
	}, testNow.Add(30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	item := f.putInput.Item
	want := map[string]string{
		"historyId":              "sms-abc123-1767323045678",
		"type":                   "sms",
		"trigger":                "CustomSMSSender_SignUp",
		"userId":                 "abc123",
		"userEmailAddress":       "user@example.com",
		"userPhoneNumber":        "+12065550100",
		"userPhoneNumberCountry": "US",
		"sentAt":                 "2026-01-02T03:04:05.678Z",
	}
	for k, v := range want {
		if got := attrS(item, k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	if got := attrN(item, "sentAtEpoch"); got != "1767323045678" {
		t.Errorf("sentAtEpoch = %s, want epoch millis", got)
	}
	// the node.js sender wrote ttl in millis, which dynamodb never expires
	if got := attrN(item, "ttl"); got != fmt.Sprint(testNow.Add(30*24*time.Hour).Unix()) {
		t.Errorf("ttl = %s, want epoch seconds", got)
	}
	if aws.ToString(f.putInput.TableName) != "history" {
		t.Errorf("TableName = %s", aws.ToString(f.putInput.TableName))
	}
}

func TestDynamoDBHistory_SaveWithoutUserID(t *testing.T) {
	f := &fakeDynamoDB{}
	if err := NewDynamoDBHistory(f, "history").Save(context.Background(), Record{UserPhoneNumber: "+12065550100", SentAt: testNow}, testNow); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.putInput.Item["userId"]; ok {
		t.Error("userId should be omitted when empty; index keys can't be empty strings")
	}
	if got := attrS(f.putInput.Item, "historyId"); got != "sms--1767323045678" {
		t.Errorf("historyId = %q", got)
	}
}

func TestDynamoDBHistory_CountByPhoneNumber(t *testing.T) {
	f := &fakeDynamoDB{count: 4}
	n, err := NewDynamoDBHistory(f, "history").CountByPhoneNumber(context.Background(), "+12065550100", time.UnixMilli(100000))
	if err != nil || n != 4 {
		t.Fatalf("CountByPhoneNumber() = %d, %v", n, err)
	}

	in := f.queryInput
	if aws.ToString(in.IndexName) != "userPhoneNumber-index" || in.Select != ddbtypes.SelectCount {
		t.Errorf("query = %+v", in)
	}
	if got := aws.ToString(in.KeyConditionExpression); got != "userPhoneNumber = :userPhoneNumber AND sentAtEpoch >= :sentAtEpoch" {
		t.Errorf("KeyConditionExpression = %q", got)
	}
	if attrS(in.ExpressionAttributeValues, ":userPhoneNumber") != "+12065550100" || attrN(in.ExpressionAttributeValues, ":sentAtEpoch") != "100000" {
		t.Errorf("ExpressionAttributeValues = %+v", in.ExpressionAttributeValues)
	}
}

func TestDynamoDBHistory_Errors(t *testing.T) {
	h := NewDynamoDBHistory(&fakeDynamoDB{err: errors.New("unavailable")}, "history")
	if err := h.Save(context.Background(), Record{UserPhoneNumber: "+12065550100", SentAt: testNow}, testNow); err == nil {
		t.Error("Save() should return the store error")
	}
	if _, err := h.CountByPhoneNumber(context.Background(), "+12065550100", testNow); err == nil {
		t.Error("CountByPhoneNumber() should return the store error")
	}
}

func TestMemoryHistory(t *testing.T) {
	h := NewMemoryHistory()
	ctx := context.Background()
	for i, phone := range []string{"+12065550100", "+12065550100", "+12065550101", "+12065550100"} {
		_ = h.Save(ctx, Record{UserPhoneNumber: phone, SentAt: testNow.Add(time.Duration(i) * time.Minute)}, testNow)
	}

	n, _ := h.CountByPhoneNumber(ctx, "+12065550100", testNow.Add(time.Minute))
	if n != 2 {
		t.Errorf("count since +1m = %d, want 2", n)
	}
	n, _ = h.CountByPhoneNumber(ctx, "+12065550100", testNow)
	if n != 3 {
		t.Errorf("count since start = %d, want 3", n)
	}
}

// dynamoDBLocalEnv points the tests at DynamoDB Local, for example
// http://localhost:8000. The tests are skipped when it is unset.
const dynamoDBLocalEnv = "DYNAMODB_LOCAL_ENDPOINT"

func TestDynamoDBHistory_Local(t *testing.T) {
	endpoint := os.Getenv(dynamoDBLocalEnv)
	if endpoint == "" {
		t.Skipf("set %s to run against DynamoDB Local", dynamoDBLocalEnv)
	}
	ctx := context.Background()

	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "local", SecretAccessKey: "local"}, nil
		}),
	})

	// same layout as the sms_history table in the terraform module
	table := fmt.Sprintf("sms-history-test-%d", time.Now().UnixNano())
	gsi := func(name, hash string) ddbtypes.GlobalSecondaryIndex {
		return ddbtypes.GlobalSecondaryIndex{
			IndexName: aws.String(name),
			KeySchema: []ddbtypes.KeySchemaElement{
				{AttributeName: aws.String(hash), KeyType: ddbtypes.KeyTypeHash},
				{AttributeName: aws.String("sentAtEpoch"), KeyType: ddbtypes.KeyTypeRange},
			},
			Projection: &ddbtypes.Projection{ProjectionType: ddbtypes.ProjectionTypeAll},
		}
	}
	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:   aws.String(table),
		BillingMode: ddbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []ddbtypes.AttributeDefinition{
			{AttributeName: aws.String("historyId"), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String("sentAtEpoch"), AttributeType: ddbtypes.ScalarAttributeTypeN},
			{AttributeName: aws.String("userId"), AttributeType: ddbtypes.ScalarAttributeTypeS},
			{AttributeName: aws.String("userPhoneNumber"), AttributeType: ddbtypes.ScalarAttributeTypeS},
		},
		KeySchema: []ddbtypes.KeySchemaElement{
			{AttributeName: aws.String("historyId"), KeyType: ddbtypes.KeyTypeHash},
			{AttributeName: aws.String("sentAtEpoch"), KeyType: ddbtypes.KeyTypeRange},
		},
		GlobalSecondaryIndexes: []ddbtypes.GlobalSecondaryIndex{gsi("userSid-index", "userId"), gsi("userPhoneNumber-index", "userPhoneNumber")},
	})
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})
	if err := dynamodb.NewTableExistsWaiter(client).Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)}, 30*time.Second); err != nil {
		t.Fatalf("wait for table: %v", err)
	}

	h := NewDynamoDBHistory(client, table)
	saves := []Record{
		{UserID: "u1", UserPhoneNumber: "+12065550100", SentAt: testNow.Add(-20 * time.Minute)},
		{UserID: "u1", UserPhoneNumber: "+12065550100", SentAt: testNow.Add(-10 * time.Minute)},
		{UserID: "u2", UserPhoneNumber: "+12065550101", SentAt: testNow.Add(-5 * time.Minute)},
		{UserID: "", UserPhoneNumber: "+12065550100", SentAt: testNow},
	}
	for _, r := range saves {
		if err := h.Save(ctx, r, testNow.Add(time.Hour)); err != nil {
			t.Fatalf("Save(%+v) error = %v", r, err)
		}
	}

	n, err := h.CountByPhoneNumber(ctx, "+12065550100", testNow.Add(-15*time.Minute))
	if err != nil || n != 2 {
		t.Errorf("CountByPhoneNumber() = %d, %v; want 2 within 15 minutes", n, err)
	}
	n, err = h.CountByPhoneNumber(ctx, "+12065550199", testNow.Add(-time.Hour))
	if err != nil || n != 0 {
		t.Errorf("CountByPhoneNumber(other) = %d, %v; want 0", n, err)
	}
}
