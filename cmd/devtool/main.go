// Command devtool runs Cognito custom sender events locally.
//
//	devtool eval -email-policy policy.rego -events events.json
//	    Evaluate policies against events and print each decision. Makes no
//	    AWS or network calls.
//
//	devtool run -events events.json
//	    Run events through the full sender with the configuration from the
//	    environment and .env. By default codes are treated as plaintext,
//	    rate limit and SMS history stores are in memory, and nothing is sent.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"

	"github.com/joho/godotenv"

	"github.com/cruxstack/cognito-custom-message-sender-go/v3/internal/logging"
)

const usage = `usage: devtool <command> [flags]

commands:
  eval   evaluate policies against events and print the decisions
  run    run events through the full sender (dry run by default)

run "devtool <command> -h" for the flags of a command`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	ctx := context.Background()
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "eval":
		err = evalCmd(ctx, args, os.Stdout)
	case "run":
		err = runCmd(ctx, args)
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

// readEvents reads a JSON file with one event object or an array of events.
func readEvents(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' {
		return []json.RawMessage{data}, nil
	}
	var events []json.RawMessage
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("%s: want an event object or an array of events: %w", path, err)
	}
	return events, nil
}

// loadDotEnv loads path into the environment without overriding variables
// that are already set. A missing file is ignored.
func loadDotEnv(path string) error {
	if path == "" {
		return nil
	}
	if err := godotenv.Load(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("load %s: %w", path, err)
	}
	return nil
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(logging.ContextHandler(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})))
}
