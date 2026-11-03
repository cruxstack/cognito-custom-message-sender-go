// Package ratelimit limits outgoing cognito emails and SMS per destination,
// per user, and per message class using fixed-window counters in a shared
// store.
package ratelimit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	ModeCount   = "count"
	ModeEnforce = "enforce"

	FailOpen   = "open"
	FailClosed = "closed"

	UserKeySub      = "sub"
	UserKeyUserName = "userName"

	DefaultMetricNamespace = "CognitoCustomMessageSender"

	maxShards = 100
)

// Channel is the delivery channel a limiter counts. Each channel has its own
// classes, defaults, counter keys, and metric names, so email and SMS can
// share one table.
type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
)

// MetricName returns the channel's name for a metric, for example
// EmailRateLimitDecision.
func (c Channel) MetricName(metric string) string {
	if c == ChannelSMS {
		return "SMS" + metric
	}
	return "Email" + metric
}

// Config is the json document read from APP_EMAIL_RATE_LIMIT_CONFIG or
// APP_SMS_RATE_LIMIT_CONFIG. Fields omitted from the document keep their
// defaults. An entry under classes replaces that class's defaults entirely.
type Config struct {
	channel Channel

	FailMode        string                 `json:"failMode"`
	MetricNamespace string                 `json:"metricNamespace"`
	Timeout         Duration               `json:"timeout"`
	DedupeTTL       Duration               `json:"dedupeTtl"`
	UserKey         string                 `json:"userKey"`
	Normalize       NormalizeConfig        `json:"normalize"`
	Exempt          ExemptConfig           `json:"exempt"`
	Global          GlobalConfig           `json:"global"`
	Classes         map[string]ClassConfig `json:"classes"`
}

type NormalizeConfig struct {
	StripPlusTag   bool `json:"stripPlusTag"`
	StripGmailDots bool `json:"stripGmailDots"`
}

type ExemptConfig struct {
	Domains []string `json:"domains"`
	Classes []string `json:"classes"`
}

type GlobalConfig struct {
	Mode            string  `json:"mode"`
	Shards          int     `json:"shards"`
	DegradeFraction float64 `json:"degradeFraction"`
}

type ClassConfig struct {
	Destination []Limit `json:"destination"`
	User        []Limit `json:"user"`
	Global      []Limit `json:"global"`
	GlobalMode  string  `json:"globalMode,omitempty"`
}

type Limit struct {
	Window Window `json:"window"`
	Max    int64  `json:"max"`
}

// DefaultConfig returns a channel's limits when its config document is
// empty. Global limits are unset by default because they depend on the
// deployment's normal traffic. SMS limits are tighter than email limits
// because each SMS costs money and SMS pumping fraud targets OTP flows.
func DefaultConfig(ch Channel) *Config {
	cfg := &Config{
		channel:         ch,
		FailMode:        FailOpen,
		MetricNamespace: DefaultMetricNamespace,
		Timeout:         Duration(time.Second),
		DedupeTTL:       Duration(6 * time.Hour),
		UserKey:         UserKeySub,
		Exempt:          ExemptConfig{Domains: []string{}, Classes: []string{ClassAdmin}},
		Global:          GlobalConfig{Mode: ModeCount, Shards: 4, DegradeFraction: 0.8},
	}

	if ch == ChannelSMS {
		cfg.Classes = map[string]ClassConfig{
			ClassAuthentication: {Destination: []Limit{{Window(15 * time.Minute), 5}, {Window(24 * time.Hour), 10}}},
			ClassSignUp:         {Destination: []Limit{{Window(time.Hour), 3}, {Window(24 * time.Hour), 5}}},
			ClassForgotPassword: {Destination: []Limit{{Window(time.Hour), 3}, {Window(24 * time.Hour), 5}}},
			ClassAttribute:      {Destination: []Limit{{Window(time.Hour), 3}}},
		}
		return cfg
	}

	cfg.Normalize = NormalizeConfig{StripPlusTag: true, StripGmailDots: true}
	cfg.Classes = map[string]ClassConfig{
		ClassAuthentication: {Destination: []Limit{{Window(15 * time.Minute), 5}, {Window(24 * time.Hour), 20}}},
		ClassSignUp:         {Destination: []Limit{{Window(time.Hour), 3}, {Window(24 * time.Hour), 10}}},
		ClassForgotPassword: {Destination: []Limit{{Window(time.Hour), 5}}},
		ClassAttribute:      {Destination: []Limit{{Window(time.Hour), 5}}},
		ClassNotification:   {Destination: []Limit{{Window(time.Hour), 3}}},
	}
	return cfg
}

// Channel returns the channel the config is for.
func (c *Config) Channel() Channel {
	if c.channel == "" {
		return ChannelEmail
	}
	return c.channel
}

// ParseConfig applies the json document in raw over the channel's defaults
// and validates the result. An empty document yields the defaults.
func ParseConfig(ch Channel, raw string) (*Config, error) {
	cfg := DefaultConfig(ch)

	if strings.TrimSpace(raw) != "" {
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("failed to parse rate limit config: %w", err)
		}
		if dec.More() {
			return nil, errors.New("failed to parse rate limit config: unexpected data after json object")
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	cfg.Exempt.Domains = normalizeDomains(cfg.Exempt.Domains)

	return cfg, nil
}

var metricNamespacePattern = regexp.MustCompile(`^[A-Za-z0-9._/#: -]{1,255}$`)

func (c *Config) Validate() error {
	var errs []error
	ch := c.Channel()
	classes := ClassesFor(ch)

	if ch != ChannelEmail && ch != ChannelSMS {
		errs = append(errs, fmt.Errorf("unknown channel %q", ch))
	}
	if ch == ChannelSMS {
		if len(c.Exempt.Domains) > 0 {
			errs = append(errs, errors.New("exempt.domains applies only to email"))
		}
		if c.Normalize.StripPlusTag || c.Normalize.StripGmailDots {
			errs = append(errs, errors.New("normalize applies only to email"))
		}
	}

	if c.FailMode != FailOpen && c.FailMode != FailClosed {
		errs = append(errs, fmt.Errorf("failMode %q must be %q or %q", c.FailMode, FailOpen, FailClosed))
	}

	if !metricNamespacePattern.MatchString(c.MetricNamespace) || strings.HasPrefix(c.MetricNamespace, "AWS/") {
		errs = append(errs, fmt.Errorf("metricNamespace %q is not a valid custom cloudwatch namespace", c.MetricNamespace))
	}

	if c.Timeout <= 0 || time.Duration(c.Timeout) > 10*time.Second {
		errs = append(errs, fmt.Errorf("timeout %s must be greater than 0 and at most 10s", c.Timeout))
	}

	if time.Duration(c.DedupeTTL) < time.Minute {
		errs = append(errs, fmt.Errorf("dedupeTtl %s must be at least 1m", c.DedupeTTL))
	}

	if c.UserKey != UserKeySub && c.UserKey != UserKeyUserName {
		errs = append(errs, fmt.Errorf("userKey %q must be %q or %q", c.UserKey, UserKeySub, UserKeyUserName))
	}

	for _, d := range c.Exempt.Domains {
		if strings.TrimSpace(d) == "" {
			errs = append(errs, errors.New("exempt.domains must not contain empty values"))
			break
		}
	}

	for _, cl := range c.Exempt.Classes {
		if !slices.Contains(classes, cl) {
			errs = append(errs, fmt.Errorf("exempt.classes: unknown %s class %q", ch, cl))
		}
	}

	if !isValidMode(c.Global.Mode) {
		errs = append(errs, fmt.Errorf("global.mode %q must be %q or %q", c.Global.Mode, ModeCount, ModeEnforce))
	}

	if c.Global.Shards < 1 || c.Global.Shards > maxShards {
		errs = append(errs, fmt.Errorf("global.shards %d must be between 1 and %d", c.Global.Shards, maxShards))
	}

	if c.Global.DegradeFraction <= 0 || c.Global.DegradeFraction > 1 {
		errs = append(errs, fmt.Errorf("global.degradeFraction %v must be greater than 0 and at most 1", c.Global.DegradeFraction))
	}

	for _, name := range slices.Sorted(maps.Keys(c.Classes)) {
		cc := c.Classes[name]
		if !slices.Contains(classes, name) {
			errs = append(errs, fmt.Errorf("classes: unknown %s class %q", ch, name))
			continue
		}
		if cc.GlobalMode != "" && !isValidMode(cc.GlobalMode) {
			errs = append(errs, fmt.Errorf("classes.%s.globalMode %q must be %q or %q", name, cc.GlobalMode, ModeCount, ModeEnforce))
		}
		errs = append(errs, validateLimits("classes."+name+".destination", cc.Destination)...)
		errs = append(errs, validateLimits("classes."+name+".user", cc.User)...)
		errs = append(errs, validateLimits("classes."+name+".global", cc.Global)...)
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid rate limit config: %w", errors.Join(errs...))
	}
	return nil
}

// GlobalMode returns the global limit mode for a class.
func (c *Config) GlobalMode(class string) string {
	if m := c.Classes[class].GlobalMode; m != "" {
		return m
	}
	return c.Global.Mode
}

func validateLimits(path string, limits []Limit) []error {
	var errs []error
	seen := map[Window]bool{}
	for i, l := range limits {
		if l.Window <= 0 {
			errs = append(errs, fmt.Errorf("%s[%d].window is required", path, i))
		}
		if l.Max < 1 {
			errs = append(errs, fmt.Errorf("%s[%d].max %d must be a positive integer", path, i, l.Max))
		}
		// two limits with the same window would share one counter
		if seen[l.Window] {
			errs = append(errs, fmt.Errorf("%s[%d].window %s is duplicated", path, i, l.Window))
		}
		seen[l.Window] = true
	}
	return errs
}

func isValidMode(m string) bool {
	return m == ModeCount || m == ModeEnforce
}

func normalizeDomains(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		out = append(out, strings.ToLower(strings.TrimSpace(d)))
	}
	return out
}

// Window is a fixed counting window written as a positive integer followed by
// a unit: s, m, h, or d (for example "15m" or "1d").
type Window time.Duration

var windowPattern = regexp.MustCompile(`^([1-9][0-9]{0,8})([smhd])$`)

var windowUnits = []struct {
	suffix string
	size   time.Duration
}{
	{"d", 24 * time.Hour},
	{"h", time.Hour},
	{"m", time.Minute},
	{"s", time.Second},
}

func ParseWindow(s string) (Window, error) {
	m := windowPattern.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid window %q: want a positive integer followed by s, m, h, or d", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid window %q: %w", s, err)
	}
	for _, u := range windowUnits {
		if u.suffix == m[2] {
			return Window(time.Duration(n) * u.size), nil
		}
	}
	return 0, fmt.Errorf("invalid window %q", s)
}

// String returns the window in its largest whole unit, so "60m" and "1h"
// format the same.
func (w Window) String() string {
	d := time.Duration(w)
	for _, u := range windowUnits {
		if d >= u.size && d%u.size == 0 {
			return strconv.FormatInt(int64(d/u.size), 10) + u.suffix
		}
	}
	return d.String()
}

func (w Window) Seconds() int64 {
	return int64(time.Duration(w) / time.Second)
}

func (w Window) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.String())
}

func (w *Window) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("window must be a string: %w", err)
	}
	v, err := ParseWindow(s)
	if err != nil {
		return err
	}
	*w = v
	return nil
}

// Duration is a time.Duration that reads and writes go duration strings in
// json (for example "500ms" or "6h").
type Duration time.Duration

func (d Duration) String() string {
	return time.Duration(d).String()
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}
