package ratelimit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type fakeDynamoDB struct {
	updateInput  *dynamodb.UpdateItemInput
	updateOutput *dynamodb.UpdateItemOutput
	putInput     *dynamodb.PutItemInput
	putErr       error
	batchCalls   int
	// unprocessed is returned for this many batch calls before succeeding
	unprocessed int
}

func (f *fakeDynamoDB) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	f.updateInput = in
	return f.updateOutput, nil
}

func (f *fakeDynamoDB) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.putInput = in
	return &dynamodb.PutItemOutput{}, f.putErr
}

func (f *fakeDynamoDB) BatchGetItem(_ context.Context, in *dynamodb.BatchGetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	f.batchCalls++
	if f.batchCalls <= f.unprocessed {
		return &dynamodb.BatchGetItemOutput{UnprocessedKeys: in.RequestItems}, nil
	}
	var items []map[string]ddbtypes.AttributeValue
	for _, ka := range in.RequestItems {
		for _, k := range ka.Keys {
			items = append(items, map[string]ddbtypes.AttributeValue{
				attrKey:   k[attrKey],
				attrCount: &ddbtypes.AttributeValueMemberN{Value: "2"},
			})
		}
	}
	return &dynamodb.BatchGetItemOutput{Responses: map[string][]map[string]ddbtypes.AttributeValue{"table": items}}, nil
}

func TestDynamoDBStore_Increment(t *testing.T) {
	f := &fakeDynamoDB{updateOutput: &dynamodb.UpdateItemOutput{
		Attributes: map[string]ddbtypes.AttributeValue{attrCount: &ddbtypes.AttributeValueMemberN{Value: "7"}},
	}}
	s := NewDynamoDBStore(f, "table")

	got, err := s.Increment(context.Background(), "k", time.Unix(1700000000, 0))
	if err != nil || got != 7 {
		t.Fatalf("Increment() = %d, %v; want 7", got, err)
	}

	in := f.updateInput
	if aws.ToString(in.TableName) != "table" || in.ReturnValues != ddbtypes.ReturnValueUpdatedNew {
		t.Errorf("UpdateItem input = %+v", in)
	}
	if !strings.HasPrefix(aws.ToString(in.UpdateExpression), "ADD #count :one") {
		t.Errorf("UpdateExpression = %q, want an atomic ADD", aws.ToString(in.UpdateExpression))
	}
	if ttl := in.ExpressionAttributeValues[":ttl"].(*ddbtypes.AttributeValueMemberN).Value; ttl != "1700000000" {
		t.Errorf("ttl = %s", ttl)
	}
}

func TestDynamoDBStore_IncrementMissingCount(t *testing.T) {
	f := &fakeDynamoDB{updateOutput: &dynamodb.UpdateItemOutput{}}
	if _, err := NewDynamoDBStore(f, "table").Increment(context.Background(), "k", time.Now()); err == nil {
		t.Error("Increment() should fail when the response has no count")
	}
}

func TestDynamoDBStore_PutIfAbsent(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantCreated bool
		wantErr     bool
	}{
		{"created", nil, true, false},
		{"exists", &ddbtypes.ConditionalCheckFailedException{}, false, false},
		{"error", errors.New("throttled"), false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeDynamoDB{putErr: tc.err}
			created, err := NewDynamoDBStore(f, "table").PutIfAbsent(context.Background(), "k", time.Now(), time.Now().Add(time.Hour))
			if created != tc.wantCreated || (err != nil) != tc.wantErr {
				t.Errorf("PutIfAbsent() = %v, %v", created, err)
			}
			if cond := aws.ToString(f.putInput.ConditionExpression); !strings.Contains(cond, "attribute_not_exists") {
				t.Errorf("ConditionExpression = %q", cond)
			}
		})
	}
}

func TestDynamoDBStore_GetRetriesUnprocessedKeys(t *testing.T) {
	f := &fakeDynamoDB{unprocessed: 2}
	got, err := NewDynamoDBStore(f, "table").Get(context.Background(), []string{"a", "b"})
	if err != nil || got["a"] != 2 || got["b"] != 2 {
		t.Fatalf("Get() = %v, %v", got, err)
	}
	if f.batchCalls != 3 {
		t.Errorf("BatchGetItem calls = %d, want 3", f.batchCalls)
	}
}

func TestDynamoDBStore_GetGivesUpOnUnprocessedKeys(t *testing.T) {
	f := &fakeDynamoDB{unprocessed: 10}
	if _, err := NewDynamoDBStore(f, "table").Get(context.Background(), []string{"a"}); err == nil {
		t.Error("Get() should fail when keys stay unprocessed")
	}
	if f.batchCalls != batchGetAttempts {
		t.Errorf("BatchGetItem calls = %d, want %d", f.batchCalls, batchGetAttempts)
	}
}
