package providers

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// mockSESv2Client implements sesv2.GetAccount for testing
type mockSESv2Client struct {
	sendingEnabled bool
	shouldError    bool
	callCount      int
}

func (m *mockSESv2Client) GetAccount(ctx context.Context, input *sesv2.GetAccountInput, opts ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error) {
	m.callCount++
	if m.shouldError {
		return nil, context.DeadlineExceeded
	}
	return &sesv2.GetAccountOutput{
		SendingEnabled: m.sendingEnabled,
	}, nil
}

// SESHealthCheckerWithMock allows injecting a mock client for testing
type SESHealthCheckerWithMock struct {
	*SESHealthChecker
	mockClient *mockSESv2Client
}

func newTestHealthChecker(mock *mockSESv2Client, cacheTTL time.Duration) *SESHealthCheckerWithMock {
	checker := &SESHealthChecker{
		cacheTTL: cacheTTL,
	}
	return &SESHealthCheckerWithMock{
		SESHealthChecker: checker,
		mockClient:       mock,
	}
}

func (h *SESHealthCheckerWithMock) IsHealthy(ctx context.Context) bool {
	// Check cache first
	h.mu.RLock()
	if time.Now().Before(h.cacheExpiry) {
		healthy := h.cachedHealthy
		h.mu.RUnlock()
		return healthy
	}
	h.mu.RUnlock()

	// Cache expired, fetch fresh status
	healthy := h.checkHealthWithMock(ctx)

	// Update cache
	h.mu.Lock()
	h.cachedHealthy = healthy
	h.cacheExpiry = time.Now().Add(h.cacheTTL)
	h.mu.Unlock()

	return healthy
}

func (h *SESHealthCheckerWithMock) checkHealthWithMock(ctx context.Context) bool {
	output, err := h.mockClient.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		return false
	}
	return output.SendingEnabled
}

func TestSESHealthChecker_Healthy(t *testing.T) {
	mock := &mockSESv2Client{sendingEnabled: true}
	checker := newTestHealthChecker(mock, 30*time.Second)

	healthy := checker.IsHealthy(context.Background())

	if !healthy {
		t.Error("expected healthy when sending is enabled")
	}
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call, got %d", mock.callCount)
	}
}

func TestSESHealthChecker_Unhealthy_SendingDisabled(t *testing.T) {
	mock := &mockSESv2Client{sendingEnabled: false}
	checker := newTestHealthChecker(mock, 30*time.Second)

	healthy := checker.IsHealthy(context.Background())

	if healthy {
		t.Error("expected unhealthy when sending is disabled")
	}
}

func TestSESHealthChecker_Unhealthy_APIError(t *testing.T) {
	mock := &mockSESv2Client{shouldError: true}
	checker := newTestHealthChecker(mock, 30*time.Second)

	healthy := checker.IsHealthy(context.Background())

	if healthy {
		t.Error("expected unhealthy when API returns error")
	}
}

func TestSESHealthChecker_CachesResult(t *testing.T) {
	mock := &mockSESv2Client{sendingEnabled: true}
	checker := newTestHealthChecker(mock, 30*time.Second)

	// First call should hit API
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call after first check, got %d", mock.callCount)
	}

	// Second call should use cache
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 1 {
		t.Errorf("expected still 1 API call (cached), got %d", mock.callCount)
	}
}

func TestSESHealthChecker_CacheExpires(t *testing.T) {
	mock := &mockSESv2Client{sendingEnabled: true}
	// Very short TTL for testing
	checker := newTestHealthChecker(mock, 10*time.Millisecond)

	// First call
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call, got %d", mock.callCount)
	}

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Second call should hit API again
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 2 {
		t.Errorf("expected 2 API calls after cache expiry, got %d", mock.callCount)
	}
}

func TestSESHealthChecker_InvalidateCache(t *testing.T) {
	mock := &mockSESv2Client{sendingEnabled: true}
	checker := newTestHealthChecker(mock, 30*time.Second)

	// First call
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 1 {
		t.Errorf("expected 1 API call, got %d", mock.callCount)
	}

	// Invalidate cache
	checker.InvalidateCache()

	// Next call should hit API
	_ = checker.IsHealthy(context.Background())
	if mock.callCount != 2 {
		t.Errorf("expected 2 API calls after invalidation, got %d", mock.callCount)
	}
}
