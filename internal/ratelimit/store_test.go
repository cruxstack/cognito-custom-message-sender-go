package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// dynamoDBEndpointEnv points the store tests at DynamoDB Local, for example
// http://localhost:8000. The DynamoDB tests are skipped when it is unset.
const dynamoDBEndpointEnv = "RATELIMIT_DYNAMODB_ENDPOINT"

func TestMemoryStore(t *testing.T) {
	testStore(t, func(t *testing.T) Store { return NewMemoryStore() })
}

func TestDynamoDBStore_Local(t *testing.T) {
	endpoint := os.Getenv(dynamoDBEndpointEnv)
	if endpoint == "" {
		t.Skipf("set %s to run against DynamoDB Local", dynamoDBEndpointEnv)
	}

	client := dynamodb.New(dynamodb.Options{
		Region:       "us-east-1",
		BaseEndpoint: aws.String(endpoint),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "local", SecretAccessKey: "local"}, nil
		}),
	})

	testStore(t, func(t *testing.T) Store {
		table := createLocalTable(t, client)
		return NewDynamoDBStore(client, table)
	})

	t.Run("limiter end to end", func(t *testing.T) {
		store := NewDynamoDBStore(client, createLocalTable(t, client))
		h := newHarness(t, globalConfig(ModeEnforce, 3, 1), store, slog.LevelError)

		var decisions []string
		for i := range 4 {
			decisions = append(decisions, h.check("CustomEmailSender_Authentication", fmt.Sprintf("user%d@example.com", i), nil).Decision)
		}
		want := []string{DecisionSent, DecisionSent, DecisionSent, DecisionThrottledGlobal}
		if fmt.Sprint(decisions) != fmt.Sprint(want) {
			t.Errorf("decisions = %v, want %v", decisions, want)
		}
	})
}

func createLocalTable(t *testing.T, client *dynamodb.Client) string {
	t.Helper()
	ctx := context.Background()
	table := fmt.Sprintf("ratelimit-test-%d", time.Now().UnixNano())

	_, err := client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(table),
		BillingMode:          ddbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []ddbtypes.AttributeDefinition{{AttributeName: aws.String(attrKey), AttributeType: ddbtypes.ScalarAttributeTypeS}},
		KeySchema:            []ddbtypes.KeySchemaElement{{AttributeName: aws.String(attrKey), KeyType: ddbtypes.KeyTypeHash}},
	})
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &dynamodb.DeleteTableInput{TableName: aws.String(table)})
	})

	waiter := dynamodb.NewTableExistsWaiter(client)
	if err := waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(table)}, 30*time.Second); err != nil {
		t.Fatalf("wait for table: %v", err)
	}
	return table
}

func testStore(t *testing.T, newStore func(t *testing.T) Store) {
	ctx := context.Background()
	expires := testStart.Add(time.Hour)

	t.Run("increment", func(t *testing.T) {
		s := newStore(t)
		for want := int64(1); want <= 3; want++ {
			got, err := s.Increment(ctx, "k1", expires)
			if err != nil || got != want {
				t.Fatalf("Increment() = %d, %v; want %d", got, err, want)
			}
		}
	})

	t.Run("concurrent increments are atomic", func(t *testing.T) {
		s := newStore(t)
		var wg sync.WaitGroup
		for range 25 {
			wg.Go(func() {
				if _, err := s.Increment(ctx, "hot", expires); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()

		got, err := s.Get(ctx, []string{"hot"})
		if err != nil || got["hot"] != 25 {
			t.Errorf("Get() = %v, %v; want 25", got, err)
		}
	})

	t.Run("get", func(t *testing.T) {
		s := newStore(t)
		// more keys than one BatchGetItem request accepts
		keys := make([]string, 0, 130)
		for i := range 130 {
			keys = append(keys, fmt.Sprintf("k%03d", i))
		}
		for i := 0; i < len(keys); i += 10 {
			for range i/10 + 1 {
				if _, err := s.Increment(ctx, keys[i], expires); err != nil {
					t.Fatal(err)
				}
			}
		}

		got, err := s.Get(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 13 {
			t.Errorf("Get() returned %d keys, want 13 (missing keys omitted)", len(got))
		}
		for i := 0; i < len(keys); i += 10 {
			if want := int64(i/10 + 1); got[keys[i]] != want {
				t.Errorf("Get()[%s] = %d, want %d", keys[i], got[keys[i]], want)
			}
		}

		empty, err := s.Get(ctx, nil)
		if err != nil || len(empty) != 0 {
			t.Errorf("Get(nil) = %v, %v", empty, err)
		}
	})

	t.Run("put if absent", func(t *testing.T) {
		s := newStore(t)
		now := testStart

		created, err := s.PutIfAbsent(ctx, "marker", now, now.Add(time.Hour))
		if err != nil || !created {
			t.Fatalf("first PutIfAbsent() = %v, %v; want true", created, err)
		}
		created, err = s.PutIfAbsent(ctx, "marker", now.Add(time.Minute), now.Add(time.Hour))
		if err != nil || created {
			t.Fatalf("second PutIfAbsent() = %v, %v; want false", created, err)
		}

		// an expired marker that ttl has not deleted yet counts as absent
		created, err = s.PutIfAbsent(ctx, "marker", now.Add(2*time.Hour), now.Add(3*time.Hour))
		if err != nil || !created {
			t.Fatalf("PutIfAbsent() after expiry = %v, %v; want true", created, err)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		s := newStore(t)
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := s.Increment(cctx, "k", expires); err == nil {
			t.Error("Increment() with a canceled context should fail")
		}
	})
}
