package ratelimit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Lines() []map[string]any {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b.buf.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err == nil {
			out = append(out, m)
		}
	}
	return out
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type harness struct {
	limiter *Limiter
	store   *MemoryStore
	clock   *fakeClock
	logs    *syncBuffer
	codes   atomic.Int64
}

func newHarness(t *testing.T, cfg *Config, store Store, level slog.Level) *harness {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid test config: %v", err)
	}
	h := &harness{clock: &fakeClock{t: testStart.Add(time.Minute)}, logs: &syncBuffer{}}
	if store == nil {
		h.store = NewMemoryStore()
		store = h.store
	}
	var shard atomic.Int64
	h.limiter = New(cfg, store,
		WithClock(h.clock.Now),
		WithShardPicker(func(n int) int { return int(shard.Add(1)-1) % n }),
		WithLogger(slog.New(slog.NewJSONHandler(h.logs, &slog.HandlerOptions{Level: level}))),
	)
	return h
}

// check sends one email with a fresh ciphertext, as cognito does per request.
func (h *harness) check(trigger, email string, attrs map[string]any) *Result {
	if attrs == nil {
		attrs = map[string]any{"email_verified": "true", "sub": "sub-1"}
	}
	return h.limiter.Check(context.Background(), Request{
		Trigger:        trigger,
		Email:          email,
		UserName:       "user-1",
		UserAttributes: attrs,
		Code:           fmt.Sprintf("ciphertext-%d", h.codes.Add(1)),
	})
}

func configWith(mutate func(c *Config)) *Config {
	c := DefaultConfig()
	mutate(c)
	return c
}

func TestBucketStart(t *testing.T) {
	at := func(s string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	tests := []struct {
		now    string
		window string
		want   string
	}{
		{"2026-01-01T00:07:30Z", "15m", "2026-01-01T00:00:00Z"},
		{"2026-01-01T00:15:00Z", "15m", "2026-01-01T00:15:00Z"},
		{"2026-01-01T00:14:59Z", "15m", "2026-01-01T00:00:00Z"},
		{"2026-01-01T13:45:00Z", "1h", "2026-01-01T13:00:00Z"},
		{"2026-01-01T13:45:00Z", "24h", "2026-01-01T00:00:00Z"},
		{"2026-01-01T13:45:00Z", "1d", "2026-01-01T00:00:00Z"},
		{"2026-01-01T13:45:00+05:00", "1d", "2026-01-01T00:00:00Z"},
		{"2026-01-01T00:00:59Z", "30s", "2026-01-01T00:00:30Z"},
		{"1969-12-31T23:59:30Z", "1m", "1969-12-31T23:59:00Z"},
	}

	for _, tc := range tests {
		t.Run(tc.now+"/"+tc.window, func(t *testing.T) {
			w, err := ParseWindow(tc.window)
			if err != nil {
				t.Fatal(err)
			}
			if got := bucketStart(at(tc.now), w); !got.Equal(at(tc.want)) {
				t.Errorf("bucketStart() = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCounterKey(t *testing.T) {
	w, _ := ParseWindow("60m")
	got := counterKey(scopeDestination, ClassSignUp, "abc", w, testStart)
	if want := fmt.Sprintf("dst#signup#abc#1h#%d", testStart.Unix()); got != want {
		t.Errorf("counterKey() = %q, want %q", got, want)
	}
}

func TestLimiter_DestinationLimit(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelDebug)

	// signup allows 3 per hour; aliases of one mailbox share the counter
	addrs := []string{"user@example.com", "User+promo@Example.com", " user+x@example.com", "user@example.com"}
	var results []*Result
	for _, a := range addrs {
		results = append(results, h.check("CustomEmailSender_SignUp", a, nil))
	}

	for i, r := range results[:3] {
		if r.Decision != DecisionSent || !r.Allowed() {
			t.Fatalf("attempt %d decision = %q, want sent", i+1, r.Decision)
		}
	}
	last := results[3]
	if last.Decision != DecisionThrottledDestination || last.Allowed() {
		t.Fatalf("attempt 4 decision = %q, want throttled_destination", last.Decision)
	}

	want := []WindowState{{"1h", 4, 3, true}, {"1d", 4, 10, false}}
	if fmt.Sprint(last.Destination) != fmt.Sprint(want) {
		t.Errorf("Destination = %+v, want %+v", last.Destination, want)
	}
	if last.Class != ClassSignUp || last.Reason != "destination_limit" {
		t.Errorf("Class = %q, Reason = %q", last.Class, last.Reason)
	}

	// a different mailbox has its own counter
	if r := h.check("CustomEmailSender_SignUp", "other@example.com", nil); r.Decision != DecisionSent {
		t.Errorf("other address decision = %q, want sent", r.Decision)
	}

	// the throttle log masks the address and carries the hash
	logs := h.logs.String()
	if !strings.Contains(logs, `"msg":"email throttled by rate limit"`) {
		t.Fatalf("missing throttle log:\n%s", logs)
	}
	if !strings.Contains(logs, "u***@example.com") || !strings.Contains(logs, Hash("user@example.com")) {
		t.Errorf("throttle log should carry the masked address and hash:\n%s", logs)
	}
	if strings.Contains(logs, "user@example.com") {
		t.Errorf("logs contain the plaintext address:\n%s", logs)
	}
}

func TestLimiter_ResendCodeSharesSignupBudget(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelError)

	triggers := []string{"CustomEmailSender_SignUp", "CustomEmailSender_ResendCode", "CustomEmailSender_ResendCode", "CustomEmailSender_ResendCode"}
	var last *Result
	for _, tr := range triggers {
		last = h.check(tr, "user@example.com", nil)
	}
	if last.Decision != DecisionThrottledDestination {
		t.Errorf("decision = %q, want throttled_destination", last.Decision)
	}
}

func TestLimiter_WindowRollover(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelError)

	for range 3 {
		h.check("CustomEmailSender_SignUp", "user@example.com", nil)
	}
	if r := h.check("CustomEmailSender_SignUp", "user@example.com", nil); r.Decision != DecisionThrottledDestination {
		t.Fatalf("decision = %q, want throttled_destination", r.Decision)
	}

	// the 1h bucket resets while the 1d bucket keeps counting
	h.clock.Advance(time.Hour)
	r := h.check("CustomEmailSender_SignUp", "user@example.com", nil)
	if r.Decision != DecisionSent {
		t.Fatalf("decision after rollover = %q, want sent", r.Decision)
	}
	want := []WindowState{{"1h", 1, 3, false}, {"1d", 5, 10, false}}
	if fmt.Sprint(r.Destination) != fmt.Sprint(want) {
		t.Errorf("Destination = %+v, want %+v", r.Destination, want)
	}
}

func TestLimiter_NormalizationFlags(t *testing.T) {
	aliases := []string{"first.last@gmail.com", "firstlast+tag@googlemail.com"}

	t.Run("enabled", func(t *testing.T) {
		h := newHarness(t, DefaultConfig(), nil, slog.LevelError)
		h.check("CustomEmailSender_ForgotPassword", aliases[0], nil)
		r := h.check("CustomEmailSender_ForgotPassword", aliases[1], nil)
		if r.Destination[0].Count != 2 {
			t.Errorf("count = %d, want aliases to share one counter", r.Destination[0].Count)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		cfg := configWith(func(c *Config) { c.Normalize = NormalizeConfig{} })
		h := newHarness(t, cfg, nil, slog.LevelError)
		h.check("CustomEmailSender_ForgotPassword", aliases[0], nil)
		r := h.check("CustomEmailSender_ForgotPassword", aliases[1], nil)
		if r.Destination[0].Count != 1 {
			t.Errorf("count = %d, want separate counters", r.Destination[0].Count)
		}
	})
}

func TestLimiter_StoresHashesOnly(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelError)
	h.check("CustomEmailSender_Authentication", "first.last@example.com", map[string]any{"sub": "sub-plain", "email_verified": "true"})

	keys := h.store.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys stored")
	}
	for _, k := range keys {
		if strings.Contains(k, "first") || strings.Contains(k, "example.com") || strings.Contains(k, "ciphertext") {
			t.Errorf("stored key %q contains plaintext", k)
		}
	}
}

func TestLimiter_UserLimit(t *testing.T) {
	for _, key := range []string{UserKeySub, UserKeyUserName} {
		t.Run(key, func(t *testing.T) {
			cfg := configWith(func(c *Config) {
				c.UserKey = key
				c.Classes[ClassAuthentication] = ClassConfig{
					Destination: []Limit{{Window(time.Hour), 100}},
					User:        []Limit{{Window(time.Hour), 2}},
				}
			})
			h := newHarness(t, cfg, nil, slog.LevelError)

			// one user, three addresses (for example after attribute changes)
			var last *Result
			for i := range 3 {
				last = h.check("CustomEmailSender_Authentication", fmt.Sprintf("user%d@example.com", i), nil)
			}
			if last.Decision != DecisionThrottledUser || last.Allowed() {
				t.Errorf("decision = %q, want throttled_user", last.Decision)
			}
			if len(last.User) != 1 || last.User[0].Count != 3 {
				t.Errorf("User = %+v", last.User)
			}
		})
	}

	t.Run("missing user id skips user limits", func(t *testing.T) {
		cfg := configWith(func(c *Config) {
			c.Classes[ClassAuthentication] = ClassConfig{User: []Limit{{Window(time.Hour), 1}}}
		})
		h := newHarness(t, cfg, nil, slog.LevelError)
		for range 3 {
			r := h.check("CustomEmailSender_Authentication", "user@example.com", map[string]any{"email_verified": "true"})
			if r.Decision != DecisionSent || len(r.User) != 0 {
				t.Fatalf("decision = %q, User = %+v; want sent without user counters", r.Decision, r.User)
			}
		}
	})
}

func globalConfig(mode string, max int64, fraction float64) *Config {
	return configWith(func(c *Config) {
		c.Global = GlobalConfig{Mode: mode, Shards: 4, DegradeFraction: fraction}
		c.Classes[ClassAuthentication] = ClassConfig{
			Destination: []Limit{{Window(time.Hour), 100}},
			Global:      []Limit{{Window(time.Hour), max}},
		}
	})
}

func TestLimiter_GlobalCountMode(t *testing.T) {
	h := newHarness(t, globalConfig(ModeCount, 10, 1), nil, slog.LevelDebug)

	var last *Result
	for i := range 11 {
		last = h.check("CustomEmailSender_Authentication", fmt.Sprintf("user%d@example.com", i), nil)
		if want := int64(i + 1); last.Global.Windows[0].Count != want {
			t.Fatalf("attempt %d global count = %d, want %d (shards summed)", i+1, last.Global.Windows[0].Count, want)
		}
	}

	if last.Decision != DecisionSent || !last.Allowed() {
		t.Errorf("decision = %q, want sent in count mode", last.Decision)
	}
	if !last.Global.WouldThrottle || !last.Global.Windows[0].Exceeded || last.Global.Mode != ModeCount {
		t.Errorf("Global = %+v, want exceeded and wouldThrottle", last.Global)
	}

	var exceeded int
	for _, line := range h.logs.Lines() {
		if line[MetricGlobalExceeded] != nil {
			exceeded++
		}
	}
	if exceeded != 1 {
		t.Errorf("global exceeded metric emitted %d times, want 1", exceeded)
	}
	if !strings.Contains(h.logs.String(), "not enforced in count mode") {
		t.Error("missing count mode warning")
	}
}

func TestLimiter_GlobalEnforceMode(t *testing.T) {
	h := newHarness(t, globalConfig(ModeEnforce, 10, 1), nil, slog.LevelError)

	for i := range 10 {
		if r := h.check("CustomEmailSender_Authentication", fmt.Sprintf("user%d@example.com", i), nil); r.Decision != DecisionSent {
			t.Fatalf("attempt %d decision = %q, want sent", i+1, r.Decision)
		}
	}
	r := h.check("CustomEmailSender_Authentication", "user10@example.com", nil)
	if r.Decision != DecisionThrottledGlobal || r.Reason != "global_limit" {
		t.Errorf("decision = %q (%s), want throttled_global (global_limit)", r.Decision, r.Reason)
	}

	// other classes have their own global budget
	if r := h.check("CustomEmailSender_ForgotPassword", "user@example.com", nil); r.Decision != DecisionSent {
		t.Errorf("forgot_password decision = %q, want sent", r.Decision)
	}
}

func TestLimiter_GlobalModePerClass(t *testing.T) {
	cfg := globalConfig(ModeEnforce, 1, 1)
	ac := cfg.Classes[ClassAuthentication]
	ac.GlobalMode = ModeCount
	cfg.Classes[ClassAuthentication] = ac
	h := newHarness(t, cfg, nil, slog.LevelError)

	h.check("CustomEmailSender_Authentication", "a@example.com", nil)
	r := h.check("CustomEmailSender_Authentication", "b@example.com", nil)
	if r.Decision != DecisionSent || r.Global.Mode != ModeCount || !r.Global.WouldThrottle {
		t.Errorf("decision = %q, Global = %+v; want class override to count mode", r.Decision, r.Global)
	}
}

func TestLimiter_GlobalDegrade(t *testing.T) {
	verified := map[string]any{"email_verified": "true", "cognito:user_status": "CONFIRMED"}
	unverified := map[string]any{"email_verified": "false", "cognito:user_status": "CONFIRMED"}
	unconfirmed := map[string]any{"email_verified": "true", "cognito:user_status": "UNCONFIRMED"}

	t.Run("enforce", func(t *testing.T) {
		h := newHarness(t, globalConfig(ModeEnforce, 10, 0.5), nil, slog.LevelError)
		for i := range 5 {
			if r := h.check("CustomEmailSender_Authentication", fmt.Sprintf("v%d@example.com", i), unverified); r.Decision != DecisionSent {
				t.Fatalf("attempt %d under the degrade threshold = %q, want sent", i+1, r.Decision)
			}
		}

		r := h.check("CustomEmailSender_Authentication", "low@example.com", unverified)
		if r.Decision != DecisionThrottledGlobal || r.Reason != "global_degrade_low_trust" || !r.LowTrust {
			t.Errorf("unverified decision = %q (%s), want throttled_global (global_degrade_low_trust)", r.Decision, r.Reason)
		}
		r = h.check("CustomEmailSender_Authentication", "new@example.com", unconfirmed)
		if r.Decision != DecisionThrottledGlobal {
			t.Errorf("unconfirmed decision = %q, want throttled_global", r.Decision)
		}

		r = h.check("CustomEmailSender_Authentication", "trusted@example.com", verified)
		if r.Decision != DecisionSent || !r.Global.Degraded || r.LowTrust {
			t.Errorf("verified decision = %q, Global = %+v; want sent while degraded", r.Decision, r.Global)
		}
	})

	t.Run("count", func(t *testing.T) {
		h := newHarness(t, globalConfig(ModeCount, 10, 0.5), nil, slog.LevelError)
		for i := range 5 {
			h.check("CustomEmailSender_Authentication", fmt.Sprintf("v%d@example.com", i), verified)
		}
		r := h.check("CustomEmailSender_Authentication", "low@example.com", unverified)
		if r.Decision != DecisionSent || !r.Global.WouldThrottle {
			t.Errorf("decision = %q, Global = %+v; want sent and wouldThrottle", r.Decision, r.Global)
		}
	})
}

func TestLimiter_DedupeRetry(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelInfo)
	req := Request{
		Trigger:        "CustomEmailSender_SignUp",
		Email:          "user@example.com",
		UserAttributes: map[string]any{"email_verified": "false"},
		Code:           "same-ciphertext",
	}

	first := h.limiter.Check(context.Background(), req)
	if first.Decision != DecisionSent || first.Destination[0].Count != 1 {
		t.Fatalf("first decision = %q, Destination = %+v", first.Decision, first.Destination)
	}

	// lambda retries deliver the same ciphertext; they are sent but not counted
	for range 3 {
		retry := h.limiter.Check(context.Background(), req)
		if retry.Decision != DecisionDeduped || !retry.Deduped || !retry.Allowed() {
			t.Fatalf("retry decision = %q, want deduped", retry.Decision)
		}
	}

	next := h.check("CustomEmailSender_SignUp", "user@example.com", nil)
	if next.Destination[0].Count != 2 {
		t.Errorf("count after retries = %d, want 2", next.Destination[0].Count)
	}

	// the marker expires after dedupeTtl
	h.clock.Advance(time.Duration(DefaultConfig().DedupeTTL) + time.Second)
	if r := h.limiter.Check(context.Background(), req); r.Decision == DecisionDeduped {
		t.Error("expired retry marker should not dedupe")
	}
}

func TestLimiter_EmptyCodeIsCountedWithoutDedupe(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelError)
	req := Request{Trigger: "CustomEmailSender_AccountTakeOverNotification", Email: "user@example.com"}

	var last *Result
	for range 4 {
		last = h.limiter.Check(context.Background(), req)
	}
	if last.Decision != DecisionThrottledDestination || last.Class != ClassNotification {
		t.Errorf("decision = %q, class = %q; want notification throttled", last.Decision, last.Class)
	}
	for _, k := range h.store.Keys() {
		if strings.HasPrefix(k, scopeDedupe) {
			t.Errorf("unexpected retry marker %q for an event without a code", k)
		}
	}
}

func TestLimiter_Exemptions(t *testing.T) {
	cfg := configWith(func(c *Config) { c.Exempt.Domains = []string{"example.org"} })

	tests := []struct {
		name       string
		trigger    string
		email      string
		wantClass  string
		wantReason string
	}{
		{"admin class", "CustomEmailSender_AdminCreateUser", "user@example.com", ClassAdmin, "exempt_class"},
		{"exempt domain", "CustomEmailSender_SignUp", "user@Example.org", ClassSignUp, "exempt_domain"},
		{"unknown trigger", "CustomEmailSender_FutureTrigger", "user@example.com", ClassUnknown, "unknown_trigger"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, cfg, nil, slog.LevelDebug)
			for range 20 {
				r := h.check(tc.trigger, tc.email, nil)
				if r.Decision != DecisionExempt || !r.Exempt || r.Class != tc.wantClass || r.Reason != tc.wantReason {
					t.Fatalf("result = %+v", r)
				}
			}
			if n := h.store.Len(); n != 0 {
				t.Errorf("store has %d items, want exempt emails to skip the store", n)
			}
		})
	}

	t.Run("admin limits apply when not exempt", func(t *testing.T) {
		cfg := configWith(func(c *Config) {
			c.Exempt.Classes = []string{}
			c.Classes[ClassAdmin] = ClassConfig{Destination: []Limit{{Window(time.Hour), 1}}}
		})
		h := newHarness(t, cfg, nil, slog.LevelError)
		h.check("CustomEmailSender_AdminCreateUser", "user@example.com", nil)
		if r := h.check("CustomEmailSender_AdminCreateUser", "user@example.com", nil); r.Decision != DecisionThrottledDestination {
			t.Errorf("decision = %q, want throttled_destination", r.Decision)
		}
	})
}

func TestLimiter_MissingEmail(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelWarn)
	r := h.check("CustomEmailSender_SignUp", "", nil)
	if r.Decision != DecisionSent || len(r.Destination) != 0 {
		t.Errorf("result = %+v, want sent without destination counters", r)
	}
	if !strings.Contains(h.logs.String(), "destination rate limits skipped") {
		t.Error("missing warning for an event without an email")
	}
}

// faultyStore wraps a MemoryStore and fails selected operations.
type faultyStore struct {
	*MemoryStore
	failPut       bool
	failGet       bool
	failIncrement func(key string) bool
	block         bool
}

var errStore = errors.New("store unavailable")

func (s *faultyStore) Increment(ctx context.Context, key string, expiresAt time.Time) (int64, error) {
	if s.block {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	if s.failIncrement != nil && s.failIncrement(key) {
		return 0, errStore
	}
	return s.MemoryStore.Increment(ctx, key, expiresAt)
}

func (s *faultyStore) Get(ctx context.Context, keys []string) (map[string]int64, error) {
	if s.failGet {
		return nil, errStore
	}
	return s.MemoryStore.Get(ctx, keys)
}

func (s *faultyStore) PutIfAbsent(ctx context.Context, key string, now, expiresAt time.Time) (bool, error) {
	if s.failPut {
		return false, errStore
	}
	return s.MemoryStore.PutIfAbsent(ctx, key, now, expiresAt)
}

func TestLimiter_StoreFailure(t *testing.T) {
	all := func(string) bool { return true }

	tests := []struct {
		name         string
		failMode     string
		store        *faultyStore
		wantDecision string
		wantAllowed  bool
	}{
		{"dedupe fails open", FailOpen, &faultyStore{failPut: true}, DecisionFailOpen, true},
		{"increment fails open", FailOpen, &faultyStore{failIncrement: all}, DecisionFailOpen, true},
		{"shard read fails open", FailOpen, &faultyStore{failGet: true}, DecisionFailOpen, true},
		{"dedupe fails closed", FailClosed, &faultyStore{failPut: true}, DecisionFailClosed, false},
		{"increment fails closed", FailClosed, &faultyStore{failIncrement: all}, DecisionFailClosed, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := globalConfig(ModeEnforce, 100, 1)
			cfg.FailMode = tc.failMode
			tc.store.MemoryStore = NewMemoryStore()
			h := newHarness(t, cfg, tc.store, slog.LevelError)

			r := h.check("CustomEmailSender_Authentication", "user@example.com", nil)
			if r.Decision != tc.wantDecision || r.Allowed() != tc.wantAllowed || r.Reason != "store_error" {
				t.Fatalf("result = %+v, want %s", r, tc.wantDecision)
			}
			if r.FailOpen != (tc.failMode == FailOpen) {
				t.Errorf("FailOpen = %v", r.FailOpen)
			}
			if !strings.Contains(h.logs.String(), "store unavailable") {
				t.Errorf("store error not logged:\n%s", h.logs.String())
			}
		})
	}
}

func TestLimiter_KnownThrottleWinsOverStoreError(t *testing.T) {
	store := &faultyStore{MemoryStore: NewMemoryStore(), failIncrement: func(k string) bool { return strings.HasPrefix(k, scopeGlobal) }}
	h := newHarness(t, globalConfig(ModeEnforce, 100, 1), store, slog.LevelError)

	ac := h.limiter.cfg.Classes[ClassAuthentication]
	ac.Destination = []Limit{{Window(time.Hour), 1}}
	h.limiter.cfg.Classes[ClassAuthentication] = ac

	if r := h.check("CustomEmailSender_Authentication", "user@example.com", nil); r.Decision != DecisionFailOpen {
		t.Fatalf("decision = %q, want fail_open while under the destination limit", r.Decision)
	}
	r := h.check("CustomEmailSender_Authentication", "user@example.com", nil)
	if r.Decision != DecisionThrottledDestination || len(r.Global.Windows) != 0 {
		t.Errorf("result = %+v, want throttled_destination with unknown global state", r)
	}
}

func TestLimiter_Timeout(t *testing.T) {
	cfg := configWith(func(c *Config) { c.Timeout = Duration(20 * time.Millisecond) })
	store := &faultyStore{MemoryStore: NewMemoryStore(), block: true}
	h := newHarness(t, cfg, store, slog.LevelError)

	start := time.Now()
	r := h.check("CustomEmailSender_SignUp", "user@example.com", nil)
	if r.Decision != DecisionFailOpen {
		t.Errorf("decision = %q, want fail_open", r.Decision)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("check took %s, want it bounded by the timeout", elapsed)
	}
}

func TestLimiter_ConcurrentChecks(t *testing.T) {
	h := newHarness(t, DefaultConfig(), nil, slog.LevelError)

	var sent atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if h.check("CustomEmailSender_SignUp", "user@example.com", nil).Allowed() {
				sent.Add(1)
			}
		})
	}
	wg.Wait()

	if sent.Load() != 3 {
		t.Errorf("sent %d emails, want exactly the limit of 3", sent.Load())
	}
}

func TestLimiter_Metrics(t *testing.T) {
	cfg := configWith(func(c *Config) { c.MetricNamespace = "Example/Test" })
	// metrics are emitted even when the log level hides info logs
	h := newHarness(t, cfg, nil, slog.LevelError)

	for range 4 {
		h.check("CustomEmailSender_SignUp", "user@example.com", nil)
	}

	var records []map[string]any
	for _, line := range h.logs.Lines() {
		if _, ok := line["_aws"]; ok {
			records = append(records, line)
		}
	}
	if len(records) != 4 {
		t.Fatalf("got %d metric records, want 4:\n%s", len(records), h.logs.String())
	}

	last := records[3]
	if last["class"] != ClassSignUp || last["decision"] != DecisionThrottledDestination || last[MetricDecision] != float64(1) {
		t.Errorf("record = %v", last)
	}

	aws := last["_aws"].(map[string]any)
	if _, ok := aws["Timestamp"].(float64); !ok {
		t.Errorf("_aws.Timestamp = %v, want epoch millis", aws["Timestamp"])
	}
	directive := aws["CloudWatchMetrics"].([]any)[0].(map[string]any)
	if directive["Namespace"] != "Example/Test" {
		t.Errorf("Namespace = %v", directive["Namespace"])
	}
	if got := fmt.Sprint(directive["Dimensions"]); got != "[[class decision]]" {
		t.Errorf("Dimensions = %s, want [[class decision]]", got)
	}
	if got := fmt.Sprint(directive["Metrics"]); !strings.Contains(got, MetricDecision) || !strings.Contains(got, "Count") {
		t.Errorf("Metrics = %s", got)
	}

	raw, _ := json.Marshal(last)
	if strings.Contains(string(raw), "example.com") {
		t.Errorf("metric record contains the address: %s", raw)
	}
}
