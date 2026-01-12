package providers

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

// SESHealthChecker checks AWS SES account status to determine if sending is enabled.
// It caches the result to avoid excessive API calls.
type SESHealthChecker struct {
	client   *sesv2.Client
	cacheTTL time.Duration

	mu            sync.RWMutex
	cachedHealthy bool
	cacheExpiry   time.Time
}

// NewSESHealthChecker creates a new SES health checker with the given SESv2 client and cache TTL.
func NewSESHealthChecker(client *sesv2.Client, cacheTTL time.Duration) *SESHealthChecker {
	return &SESHealthChecker{
		client:   client,
		cacheTTL: cacheTTL,
	}
}

// IsHealthy returns true if SES sending is enabled for the account.
// The result is cached for the configured TTL to avoid excessive API calls.
func (h *SESHealthChecker) IsHealthy(ctx context.Context) bool {
	// Check cache first
	h.mu.RLock()
	if time.Now().Before(h.cacheExpiry) {
		healthy := h.cachedHealthy
		h.mu.RUnlock()
		return healthy
	}
	h.mu.RUnlock()

	// Cache expired, fetch fresh status
	healthy := h.checkHealth(ctx)

	// Update cache
	h.mu.Lock()
	h.cachedHealthy = healthy
	h.cacheExpiry = time.Now().Add(h.cacheTTL)
	h.mu.Unlock()

	return healthy
}

// checkHealth calls the SES GetAccount API to determine if sending is enabled.
func (h *SESHealthChecker) checkHealth(ctx context.Context) bool {
	output, err := h.client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		slog.WarnContext(ctx, "ses health check failed", "error", err)
		// On API error, assume unhealthy to trigger failover
		return false
	}

	// Check if sending is enabled
	if !output.SendingEnabled {
		slog.WarnContext(ctx, "ses sending is disabled",
			"enforcement_status", safeString(output.EnforcementStatus),
			"production_access", output.ProductionAccessEnabled,
		)
		return false
	}

	return true
}

// safeString safely dereferences a string pointer, returning empty string if nil.
func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// InvalidateCache forces the next IsHealthy call to fetch fresh status.
func (h *SESHealthChecker) InvalidateCache() {
	h.mu.Lock()
	h.cacheExpiry = time.Time{}
	h.mu.Unlock()
}
