package ratelimit

import (
	"context"
	"log/slog"
	"time"
)

const (
	// MetricDecision counts every checked email by class and decision.
	MetricDecision = "EmailRateLimitDecision"
	// MetricGlobalExceeded counts emails that the global limits throttle in
	// enforce mode, or would throttle in count mode.
	MetricGlobalExceeded = "EmailRateLimitGlobalExceeded"
)

// emitMetrics writes one cloudwatch embedded metric format record through the
// handler. It calls the handler directly so metrics are emitted at any log
// level. Dimensions are limited to class and decision.
func emitMetrics(ctx context.Context, h slog.Handler, namespace string, res *Result, c *check) {
	metrics := []map[string]string{{"Name": MetricDecision, "Unit": "Count"}}
	values := []slog.Attr{slog.Int(MetricDecision, 1)}
	if res.Global.WouldThrottle {
		metrics = append(metrics, map[string]string{"Name": MetricGlobalExceeded, "Unit": "Count"})
		values = append(values, slog.Int(MetricGlobalExceeded, 1))
	}

	now := time.Now()
	r := slog.NewRecord(now, slog.LevelInfo, "email rate limit metrics", 0)
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
