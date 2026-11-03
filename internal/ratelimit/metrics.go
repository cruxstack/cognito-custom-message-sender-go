package ratelimit

import (
	"context"
	"log/slog"
	"time"
)

// Metrics, named per channel with Channel.MetricName (for example
// EmailRateLimitDecision and SMSRateLimitDecision).
const (
	// MetricDecision counts every checked message by class and decision.
	MetricDecision = "RateLimitDecision"
	// MetricGlobalExceeded counts messages that the global limits throttle
	// in enforce mode, or would throttle in count mode.
	MetricGlobalExceeded = "RateLimitGlobalExceeded"
)

// emitMetrics writes one cloudwatch embedded metric format record through the
// handler. It calls the handler directly so metrics are emitted at any log
// level. Dimensions are limited to class and decision.
func emitMetrics(ctx context.Context, h slog.Handler, ch Channel, namespace string, res *Result, c *check) {
	decision, exceeded := ch.MetricName(MetricDecision), ch.MetricName(MetricGlobalExceeded)
	metrics := []map[string]string{{"Name": decision, "Unit": "Count"}}
	values := []slog.Attr{slog.Int(decision, 1)}
	if res.Global.WouldThrottle {
		metrics = append(metrics, map[string]string{"Name": exceeded, "Unit": "Count"})
		values = append(values, slog.Int(exceeded, 1))
	}

	now := time.Now()
	r := slog.NewRecord(now, slog.LevelInfo, string(ch)+" rate limit metrics", 0)
	r.AddAttrs(slog.Any("_aws", map[string]any{
		"Timestamp": now.UnixMilli(),
		"CloudWatchMetrics": []map[string]any{{
			"Namespace":  namespace,
			"Dimensions": [][]string{{"class", "decision"}},
			"Metrics":    metrics,
		}},
	}))
	r.AddAttrs(
		slog.String("class", res.Class),
		slog.String("decision", res.Decision),
		slog.String("trigger", c.req.Trigger),
		slog.Int64("latency_ms", c.latency.Milliseconds()),
	)
	r.AddAttrs(values...)

	_ = h.Handle(ctx, r)
}
