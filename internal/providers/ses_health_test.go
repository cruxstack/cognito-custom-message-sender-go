package providers

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type mockSESAccountAPI struct {
	sendingEnabled bool
	err            error
	callCount      int
}

func (m *mockSESAccountAPI) GetAccount(ctx context.Context, input *sesv2.GetAccountInput, opts ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return &sesv2.GetAccountOutput{SendingEnabled: m.sendingEnabled}, nil
}

func TestSESHealthChecker_Healthy(t *testing.T) {
	mock := &mockSESAccountAPI{sendingEnabled: true}
	checker := NewSESHealthChecker(mock, 30*time.Second)

	if !checker.IsHealthy(context.Background()) {
		t.Error("expected healthy when sending is enabled")
	}
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call, got %d", mock.callCount)
	}
}

func TestSESHealthChecker_Unhealthy_SendingDisabled(t *testing.T) {
	checker := NewSESHealthChecker(&mockSESAccountAPI{sendingEnabled: false}, 30*time.Second)

	if checker.IsHealthy(context.Background()) {
		t.Error("expected unhealthy when sending is disabled")
	}
}

func TestSESHealthChecker_Unhealthy_APIError(t *testing.T) {
	checker := NewSESHealthChecker(&mockSESAccountAPI{err: context.DeadlineExceeded}, 30*time.Second)

	if checker.IsHealthy(context.Background()) {
		t.Error("expected unhealthy when API returns error")
	}
}

func TestSESHealthChecker_CachesResult(t *testing.T) {
	mock := &mockSESAccountAPI{sendingEnabled: true}
	checker := NewSESHealthChecker(mock, 30*time.Second)

	checker.IsHealthy(context.Background())
	mock.sendingEnabled = false

	if !checker.IsHealthy(context.Background()) {
		t.Error("expected cached healthy result")
	}
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call (cached), got %d", mock.callCount)
	}
}

func TestSESHealthChecker_CacheExpires(t *testing.T) {
	mock := &mockSESAccountAPI{sendingEnabled: true}
	checker := NewSESHealthChecker(mock, 10*time.Millisecond)

	checker.IsHealthy(context.Background())
	time.Sleep(20 * time.Millisecond)
	checker.IsHealthy(context.Background())

	if mock.callCount != 2 {
		t.Errorf("expected 2 API calls after cache expiry, got %d", mock.callCount)
	}
}
