package providers

import "context"

// HealthChecker is an optional interface that providers can implement
// to enable proactive health checking for failover decisions.
type HealthChecker interface {
	// IsHealthy returns true if the provider is healthy and able to send emails.
	// Implementations should cache the result to avoid excessive API calls.
	IsHealthy(ctx context.Context) bool
}
