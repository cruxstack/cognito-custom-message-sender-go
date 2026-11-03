package ratelimit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	ClassAuthentication = "authentication"
	ClassSignUp         = "signup"
	ClassForgotPassword = "forgot_password"
	ClassAttribute      = "attribute"
	ClassAdmin          = "admin"
	ClassNotification   = "notification"

	// ClassUnknown is reported for trigger sources this package does not
	// recognize. Those emails are allowed and not counted.
	ClassUnknown = "unknown"
)

// Classes lists the message classes that can be configured.
var Classes = []string{
	ClassAuthentication,
	ClassSignUp,
	ClassForgotPassword,
	ClassAttribute,
	ClassAdmin,
	ClassNotification,
}

var triggerClasses = map[string]string{
	"CustomEmailSender_Authentication":              ClassAuthentication,
	"CustomEmailSender_SignUp":                      ClassSignUp,
	"CustomEmailSender_ResendCode":                  ClassSignUp,
	"CustomEmailSender_ForgotPassword":              ClassForgotPassword,
	"CustomEmailSender_UpdateUserAttribute":         ClassAttribute,
	"CustomEmailSender_VerifyUserAttribute":         ClassAttribute,
	"CustomEmailSender_AdminCreateUser":             ClassAdmin,
	"CustomEmailSender_AccountTakeOverNotification": ClassNotification,
}

// Classify maps a cognito custom email sender trigger source to its message
// class. It returns ClassUnknown and false for unrecognized triggers.
func Classify(trigger string) (string, bool) {
	if c, ok := triggerClasses[trigger]; ok {
		return c, true
	}
	return ClassUnknown, false
}

var gmailDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

// NormalizeAddress returns the form of an email address used for counting, so
// that aliases of one mailbox share a counter. It trims and lowercases the
// address, optionally removes a "+tag" from the local part, and optionally
// removes dots from gmail local parts (mapping googlemail.com to gmail.com).
func NormalizeAddress(addr string, opts NormalizeConfig) string {
	addr = strings.ToLower(strings.TrimSpace(addr))

	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return addr
	}
	local, domain := addr[:at], addr[at+1:]

	if opts.StripPlusTag {
		if i := strings.IndexByte(local, '+'); i > 0 {
			local = local[:i]
		}
	}

	if opts.StripGmailDots && gmailDomains[domain] {
		if stripped := strings.ReplaceAll(local, ".", ""); stripped != "" {
			local = stripped
		}
		domain = "gmail.com"
	}

	return local + "@" + domain
}

// AddressDomain returns the lowercased domain of an email address, or "" when
// the address has no domain.
func AddressDomain(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

// Hash returns the hex sha-256 digest of s. Counter keys and logs carry this
// digest instead of the address or code.
func Hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// LowTrust reports whether a recipient should be throttled first when a
// class nears its global limit, along with the reason. A recipient is low
// trust when the user is unconfirmed or the email address is not verified.
// Cognito does not document which attributes each trigger includes, so a
// missing email_verified attribute counts as unverified.
func LowTrust(attrs map[string]any) (bool, string) {
	if strings.EqualFold(attrString(attrs, "cognito:user_status"), "UNCONFIRMED") {
		return true, "user_unconfirmed"
	}

	v, ok := attrs["email_verified"]
	if !ok || v == nil {
		return true, "email_verified_missing"
	}
	switch t := v.(type) {
	case bool:
		if t {
			return false, ""
		}
	case string:
		if strings.EqualFold(strings.TrimSpace(t), "true") {
			return false, ""
		}
	}
	return true, "email_unverified"
}

func attrString(attrs map[string]any, key string) string {
	s, _ := attrs[key].(string)
	return strings.TrimSpace(s)
}
