package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	attrKey   = "pk"
	attrCount = "count"
	attrTTL   = "ttl"

	// BatchGetItem accepts at most 100 keys per request
	batchGetLimit    = 100
	batchGetAttempts = 3
)

// DynamoDBAPI is the subset of the dynamodb client used by DynamoDBStore.
type DynamoDBAPI interface {
	UpdateItem(ctx context.Context, params *dynamodb.UpdateItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error)
	PutItem(ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
	BatchGetItem(ctx context.Context, params *dynamodb.BatchGetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error)
}

// DynamoDBStore keeps counters in a dynamodb table with a string partition
// key named "pk" and a ttl attribute named "ttl".
type DynamoDBStore struct {
	client DynamoDBAPI
	table  string
}

func NewDynamoDBStore(client DynamoDBAPI, table string) *DynamoDBStore {
	return &DynamoDBStore{client: client, table: table}
}

func (s *DynamoDBStore) Increment(ctx context.Context, key string, expiresAt time.Time) (int64, error) {
	out, err := s.client.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              keyAttr(key),
		UpdateExpression: aws.String("ADD #count :one SET #ttl = :ttl"),
		ExpressionAttributeNames: map[string]string{
			"#count": attrCount,
			"#ttl":   attrTTL,
		},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":one": &ddbtypes.AttributeValueMemberN{Value: "1"},
			":ttl": epochAttr(expiresAt),
		},
		ReturnValues: ddbtypes.ReturnValueUpdatedNew,
	})
	if err != nil {
		return 0, fmt.Errorf("dynamodb update item: %w", err)
	}
	return countAttr(out.Attributes)
}

func (s *DynamoDBStore) Get(ctx context.Context, keys []string) (map[string]int64, error) {
	out := make(map[string]int64, len(keys))

	for start := 0; start < len(keys); start += batchGetLimit {
		chunk := keys[start:min(start+batchGetLimit, len(keys))]

		req := make([]map[string]ddbtypes.AttributeValue, 0, len(chunk))
		for _, k := range chunk {
			req = append(req, keyAttr(k))
		}
		pending := map[string]ddbtypes.KeysAndAttributes{
			s.table: {
				Keys:                     req,
				ProjectionExpression:     aws.String("#pk, #count"),
				ExpressionAttributeNames: map[string]string{"#pk": attrKey, "#count": attrCount},
			},
		}

		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt == batchGetAttempts {
				return nil, errors.New("dynamodb batch get item: unprocessed keys remain after retries")
			}
			if attempt > 0 {
				if err := sleep(ctx, time.Duration(attempt)*10*time.Millisecond); err != nil {
					return nil, err
				}
			}

			resp, err := s.client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{RequestItems: pending})
			if err != nil {
				return nil, fmt.Errorf("dynamodb batch get item: %w", err)
			}
			for _, item := range resp.Responses[s.table] {
				k, ok := item[attrKey].(*ddbtypes.AttributeValueMemberS)
				if !ok {
					continue
				}
				n, err := countAttr(item)
				if err != nil {
					return nil, err
				}
				out[k.Value] = n
			}
			pending = resp.UnprocessedKeys
		}
	}

	return out, nil
}

func (s *DynamoDBStore) PutIfAbsent(ctx context.Context, key string, now, expiresAt time.Time) (bool, error) {
	item := keyAttr(key)
	item[attrTTL] = epochAttr(expiresAt)

	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      item,
		// ttl deletion lags expiry, so an expired marker counts as absent
		ConditionExpression:      aws.String("attribute_not_exists(#pk) OR #ttl < :now"),
		ExpressionAttributeNames: map[string]string{"#pk": attrKey, "#ttl": attrTTL},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":now": epochAttr(now),
		},
	})

	var ccf *ddbtypes.ConditionalCheckFailedException
	switch {
	case errors.As(err, &ccf):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("dynamodb put item: %w", err)
	default:
		return true, nil
	}
}

func keyAttr(key string) map[string]ddbtypes.AttributeValue {
	return map[string]ddbtypes.AttributeValue{attrKey: &ddbtypes.AttributeValueMemberS{Value: key}}
}

func epochAttr(t time.Time) *ddbtypes.AttributeValueMemberN {
	return &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(t.Unix(), 10)}
}

func countAttr(item map[string]ddbtypes.AttributeValue) (int64, error) {
	v, ok := item[attrCount].(*ddbtypes.AttributeValueMemberN)
	if !ok {
		return 0, errors.New("dynamodb item is missing a numeric count attribute")
	}
	n, err := strconv.ParseInt(v.Value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("dynamodb item has an invalid count: %w", err)
	}
	return n, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
