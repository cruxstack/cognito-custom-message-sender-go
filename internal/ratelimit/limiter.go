package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
)

const (
	// DecisionSent means the message is within limits and continues to the
	// policy and provider. The policy can still deny it.
	DecisionSent                 = "sent"
	DecisionThrottledDestination = "throttled_destination"
	DecisionThrottledUser        = "throttled_user"
	DecisionThrottledGlobal      = "throttled_global"
	DecisionDeduped              = "deduped"
	DecisionExempt               = "exempt"
	DecisionFailOpen             = "fail_open"
	DecisionFailClosed           = "fail_closed"
)

const (
	scopeDestination = "dst"
	scopeUser        = "usr"
	scopeGlobal      = "glb"
	scopeDedupe      = "dedupe"

	// counters outlive their window so recent buckets can be inspected
	ttlSlack = time.Hour
)

// Request describes one custom email or SMS sender event.
type Request struct {
	Trigger string
	// Destination is the email address or E.164 phone number.
	Destination    string
	UserName       string
	UserAttributes map[string]any
	// Code is the encrypted code from the event. Lambda retries carry the
	// same ciphertext, so its hash identifies a retry.
	Code string
}

// Result is the outcome of a rate limit check. It is also passed to the
// policy as input.rateLimit.
type Result struct {
	Class       string        `json:"class"`
	Decision    string        `json:"decision"`
	Reason      string        `json:"reason,omitempty"`
	Exempt      bool          `json:"exempt"`
	Deduped     bool          `json:"deduped"`
	FailOpen    bool          `json:"failOpen"`
	LowTrust    bool          `json:"lowTrust"`
	Destination []WindowState `json:"destination"`
	User        []WindowState `json:"user"`
	Global      GlobalState   `json:"global"`
}

// WindowState reports one counter after this email was counted.
type WindowState struct {
	Window   string `json:"window"`
	Count    int64  `json:"count"`
	Max      int64  `json:"max"`
	Exceeded bool   `json:"exceeded"`
}

type GlobalState struct {
	Mode    string        `json:"mode"`
	Windows []WindowState `json:"windows"`
	// Degraded is true when a window's count passed the degrade fraction of
	// its max.
	Degraded bool `json:"degraded"`
	// WouldThrottle is true when the global limits throttle this email in
	// enforce mode, or would throttle it in count mode.
	WouldThrottle bool `json:"wouldThrottle"`
}

// Allowed reports whether the message may be sent. A nil result is allowed.
func (r *Result) Allowed() bool {
	if r == nil {
		return true
	}
	switch r.Decision {
	case DecisionThrottledDestination, DecisionThrottledUser, DecisionThrottledGlobal, DecisionFailClosed:
		return false
	}
	return true
}

type Limiter struct {
	cfg    *Config
	store  Store
	now    func() time.Time
	shard  func(n int) int
	logger *slog.Logger
}

type Option func(*Limiter)

// WithClock sets the clock used for window buckets and retry markers.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// WithShardPicker sets how a global counter shard is chosen for each email.
func WithShardPicker(pick func(n int) int) Option {
	return func(l *Limiter) { l.shard = pick }
}

// WithLogger sets the logger for decisions and metrics. It defaults to
// slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(l *Limiter) { l.logger = logger }
}

func New(cfg *Config, store Store, opts ...Option) *Limiter {
	l := &Limiter{cfg: cfg, store: store, now: time.Now, shard: rand.IntN}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

func (l *Limiter) log() *slog.Logger {
	if l.logger != nil {
		return l.logger
	}
	return slog.Default()
}

// Check classifies the message, applies exemptions, detects retries, counts
// the attempt, and decides whether it may be sent. It never returns an
// error: store failures resolve to fail_open or fail_closed per the config.
func (l *Limiter) Check(ctx context.Context, req Request) *Result {
	started := time.Now()
	now := l.now()
	ch := l.cfg.Channel()

	class, known := Classify(req.Trigger)
	lowTrust, trustReason := LowTrust(ch, req.UserAttributes)
	res := &Result{
		Class:       class,
		LowTrust:    lowTrust,
		Destination: []WindowState{},
		User:        []WindowState{},
		Global:      GlobalState{Mode: l.cfg.GlobalMode(class), Windows: []WindowState{}},
	}

	c := check{req: req, addr: l.normalize(req.Destination), trustReason: trustReason}
	defer func() {
		c.latency = time.Since(started)
		l.report(ctx, res, &c)
	}()

	switch {
	case !known:
		res.Decision, res.Exempt, res.Reason = DecisionExempt, true, "unknown_trigger"
		return res
	case slices.Contains(l.cfg.Exempt.Classes, class):
		res.Decision, res.Exempt, res.Reason = DecisionExempt, true, "exempt_class"
		return res
	case ch == ChannelEmail && slices.Contains(l.cfg.Exempt.Domains, AddressDomain(req.Destination)):
		res.Decision, res.Exempt, res.Reason = DecisionExempt, true, "exempt_domain"
		return res
	}

	cctx, cancel := context.WithTimeout(ctx, time.Duration(l.cfg.Timeout))
	defer cancel()

	if req.Code != "" {
		key := string(ch) + "#" + scopeDedupe + "#" + Hash(req.Code)
		created, err := l.store.PutIfAbsent(cctx, key, now, now.Add(time.Duration(l.cfg.DedupeTTL)))
		if err != nil {
			c.err = err
			l.applyFailMode(res)
			return res
		}
		if !created {
			res.Decision, res.Deduped, res.Reason = DecisionDeduped, true, "retry"
			return res
		}
	}

	dst, usr, glb := l.count(cctx, now, class, c.addr, l.userID(req))
	c.err = l.decide(res, dst, usr, glb)
	return res
}

// normalize returns the destination form used for counting.
func (l *Limiter) normalize(dst string) string {
	if l.cfg.Channel() == ChannelSMS {
		return strings.TrimSpace(dst)
	}
	return NormalizeAddress(dst, l.cfg.Normalize)
}

type check struct {
	req         Request
	addr        string
	trustReason string
	err         error
	latency     time.Duration
}

type counter struct {
	limit   Limit
	key     string
	expires time.Time
	// peers are the other shards of a global counter, summed into count
	peers []string
	count int64
	err   error
}

func (l *Limiter) userID(req Request) string {
	if l.cfg.UserKey == UserKeyUserName {
		return req.UserName
	}
	return attrString(req.UserAttributes, "sub")
}

// count increments every counter for the message concurrently and sums the
// shards of each global counter.
func (l *Limiter) count(ctx context.Context, now time.Time, class, addr, userID string) (dst, usr, glb []*counter) {
	cc := l.cfg.Classes[class]
	ch := l.cfg.Channel()

	newCounter := func(scope, id string, lim Limit) *counter {
		start := bucketStart(now, lim.Window)
		return &counter{
			limit:   lim,
			key:     counterKey(ch, scope, class, id, lim.Window, start),
			expires: start.Add(time.Duration(lim.Window)).Add(ttlSlack),
		}
	}

	if addr != "" {
		dstID := Hash(addr)
		for _, lim := range cc.Destination {
			dst = append(dst, newCounter(scopeDestination, dstID, lim))
		}
	}
	if userID != "" {
		usrID := Hash(userID)
		for _, lim := range cc.User {
			usr = append(usr, newCounter(scopeUser, usrID, lim))
		}
	}

	var peers []string
	if len(cc.Global) > 0 {
		shards := l.cfg.Global.Shards
		shard := l.shard(shards)
		for _, lim := range cc.Global {
			g := newCounter(scopeGlobal, strconv.Itoa(shard), lim)
			start := bucketStart(now, lim.Window)
			for i := range shards {
				if i != shard {
					g.peers = append(g.peers, counterKey(ch, scopeGlobal, class, strconv.Itoa(i), lim.Window, start))
				}
			}
			peers = append(peers, g.peers...)
			glb = append(glb, g)
		}
	}

	var (
		wg         sync.WaitGroup
		peerCounts map[string]int64
		peerErr    error
	)
	for _, ctr := range slices.Concat(dst, usr, glb) {
		wg.Go(func() {
			ctr.count, ctr.err = l.store.Increment(ctx, ctr.key, ctr.expires)
		})
	}
	if len(peers) > 0 {
		wg.Go(func() {
			peerCounts, peerErr = l.store.Get(ctx, peers)
		})
	}
	wg.Wait()

	for _, g := range glb {
		if g.err != nil {
			continue
		}
		if peerErr != nil {
			g.err = peerErr
			continue
		}
		for _, p := range g.peers {
			g.count += peerCounts[p]
		}
	}

	return dst, usr, glb
}

// decide fills in the window states and the decision. A known throttle wins
// over a store error; otherwise any store error applies the fail mode.
func (l *Limiter) decide(res *Result, dst, usr, glb []*counter) error {
	var errs []error
	states := func(counters []*counter) []WindowState {
		out := []WindowState{}
		for _, c := range counters {
			if c.err != nil {
				errs = append(errs, c.err)
				continue
			}
			out = append(out, WindowState{
				Window:   c.limit.Window.String(),
				Count:    c.count,
				Max:      c.limit.Max,
				Exceeded: c.count > c.limit.Max,
			})
		}
		return out
	}

	res.Destination = states(dst)
	res.User = states(usr)
	res.Global.Windows = states(glb)

	overMax := false
	for _, w := range res.Global.Windows {
		if w.Exceeded {
			overMax = true
		}
		if float64(w.Count) > l.cfg.Global.DegradeFraction*float64(w.Max) {
			res.Global.Degraded = true
		}
	}
	res.Global.WouldThrottle = overMax || (res.Global.Degraded && res.LowTrust)

	switch {
	case anyExceeded(res.Destination):
		res.Decision, res.Reason = DecisionThrottledDestination, "destination_limit"
	case anyExceeded(res.User):
		res.Decision, res.Reason = DecisionThrottledUser, "user_limit"
	case res.Global.WouldThrottle && res.Global.Mode == ModeEnforce:
		res.Decision, res.Reason = DecisionThrottledGlobal, "global_limit"
		if !overMax {
			res.Reason = "global_degrade_low_trust"
		}
	case len(errs) > 0:
		l.applyFailMode(res)
	default:
		res.Decision = DecisionSent
	}

	return errors.Join(errs...)
}

func (l *Limiter) applyFailMode(res *Result) {
	res.Reason = "store_error"
	if l.cfg.FailMode == FailClosed {
		res.Decision = DecisionFailClosed
		return
	}
	res.Decision, res.FailOpen = DecisionFailOpen, true
}

func (l *Limiter) report(ctx context.Context, res *Result, c *check) {
	log := l.log()
	ch := l.cfg.Channel()
	kind := string(ch) // used in log messages: "email ..." or "sms ..."

	emitMetrics(ctx, log.Handler(), ch, l.cfg.MetricNamespace, res, c)

	masked := logging.MaskEmail(c.addr)
	if ch == ChannelSMS {
		masked = logging.MaskPhone(c.addr)
	}

	attrs := []any{
		"class", res.Class,
		"trigger", c.req.Trigger,
		"decision", res.Decision,
		"reason", res.Reason,
		"dst_masked", masked,
		"dst_hash", hashOrEmpty(c.addr),
		"latency_ms", c.latency.Milliseconds(),
	}

	switch res.Decision {
	case DecisionThrottledDestination, DecisionThrottledUser, DecisionThrottledGlobal:
		attrs = append(attrs,
			"low_trust", res.LowTrust,
			"trust_reason", c.trustReason,
			"destination", res.Destination,
			"user", res.User,
			"global", res.Global,
		)
		if c.err != nil {
			attrs = append(attrs, "store_error", c.err)
		}
		log.WarnContext(ctx, kind+" throttled by rate limit", attrs...)
	case DecisionFailOpen, DecisionFailClosed:
		log.ErrorContext(ctx, kind+" rate limit store error", append(attrs, "error", c.err)...)
	case DecisionDeduped:
		log.InfoContext(ctx, kind+" rate limit retry detected, counters not incremented", attrs...)
	case DecisionExempt:
		if res.Reason == "unknown_trigger" {
			log.WarnContext(ctx, "unknown trigger, skipping "+kind+" rate limit", attrs...)
		} else {
			log.DebugContext(ctx, kind+" exempt from rate limit", attrs...)
		}
	default:
		if c.addr == "" && len(l.cfg.Classes[res.Class].Destination) > 0 {
			log.WarnContext(ctx, kind+" destination missing, destination rate limits skipped", attrs...)
		}
		if res.Global.WouldThrottle {
			log.WarnContext(ctx, "global "+kind+" rate limit exceeded, not enforced in count mode",
				append(attrs, "low_trust", res.LowTrust, "global", res.Global)...)
		} else {
			log.DebugContext(ctx, kind+" within rate limits",
				append(attrs, "destination", res.Destination, "user", res.User, "global", res.Global)...)
		}
	}
}

func anyExceeded(states []WindowState) bool {
	return slices.ContainsFunc(states, func(w WindowState) bool { return w.Exceeded })
}

func hashOrEmpty(s string) string {
	if s == "" {
		return ""
	}
	return Hash(s)
}

// bucketStart returns the start of the fixed window containing now. Windows
// are aligned to the unix epoch, so a 1d window starts at 00:00 UTC.
func bucketStart(now time.Time, w Window) time.Time {
	size := w.Seconds()
	ts := now.Unix()
	start := ts - ts%size
	if ts < 0 && ts%size != 0 {
		start -= size
	}
	return time.Unix(start, 0).UTC()
}

func counterKey(ch Channel, scope, class, id string, w Window, start time.Time) string {
	return fmt.Sprintf("%s#%s#%s#%s#%s#%d", ch, scope, class, id, w, start.Unix())
}
