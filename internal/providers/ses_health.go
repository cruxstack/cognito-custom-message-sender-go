package providers

import (
	"context"
	"log/slog"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
)

type SESAccountAPI interface {
	GetAccount(ctx context.Context, params *sesv2.GetAccountInput, optFns ...func(*sesv2.Options)) (*sesv2.GetAccountOutput, error)
}

type SESHealthChecker struct {
	client   SESAccountAPI
	cacheTTL time.Duration

	mu            sync.RWMutex
	cachedHealthy bool
	cacheExpiry   time.Time
}

func NewSESHealthChecker(client SESAccountAPI, cacheTTL time.Duration) *SESHealthChecker {
	return &SESHealthChecker{
		client:   client,
		cacheTTL: cacheTTL,
	}
}

func (h *SESHealthChecker) IsHealthy(ctx context.Context) bool {
	h.mu.RLock()
	if time.Now().Before(h.cacheExpiry) {
		healthy := h.cachedHealthy
		h.mu.RUnlock()
		return healthy
	}
	h.mu.RUnlock()

	healthy := h.checkHealth(ctx)

	h.mu.Lock()
	h.cachedHealthy = healthy
	h.cacheExpiry = time.Now().Add(h.cacheTTL)
	h.mu.Unlock()

	return healthy
}

func (h *SESHealthChecker) checkHealth(ctx context.Context) bool {
	output, err := h.client.GetAccount(ctx, &sesv2.GetAccountInput{})
	if err != nil {
		slog.WarnContext(ctx, "ses health check failed", "error", err)
		return false
	}

	if !output.SendingEnabled {
		slog.WarnContext(ctx, "ses sending is disabled",
			"enforcement_status", awssdk.ToString(output.EnforcementStatus),
			"production_access", output.ProductionAccessEnabled,
		)
		return false
	}

	return true
}
