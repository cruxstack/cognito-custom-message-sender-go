package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/charmbracelet/log"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/aws"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/config"
	"github.com/cruxstack/cognito-custom-message-sender-go/internal/sender"
	"github.com/joho/godotenv"
)

var (
	dataPath   string
	policyPath string
)

func init() {
	flag.StringVar(&dataPath, "data", "", "path to JSON file with test event data")
	flag.StringVar(&policyPath, "policy", "", "override path to Rego policy file")
	flag.Parse()
}

type DebugConfig struct {
	config.Config
	DataPath string
}

func NewDebugConfig() (*config.Config, error) {
	envpath := filepath.Join("..", "..", ".env")
	if _, err := os.Stat(envpath); err == nil {
		_ = godotenv.Load(envpath)
	}

	cfg, err := config.New()
	if err != nil {
		return nil, err
	}

	cfg.DebugMode = true

	if cfg.AppKmsKeyId == "" {
		cfg.AppKmsKeyId = "MOCKED_KEY_ID"
	}

	if cfg.AppEmailSenderPolicyPath == "" {
		cfg.AppEmailSenderPolicyPath = filepath.Join("..", "..", "fixtures", "debug-policy.rego")
	}
	if policyPath != "" {
		cfg.AppEmailSenderPolicyPath = policyPath
	}

	if cfg.DebugDataPath == "" {
		cfg.DebugDataPath = filepath.Join("..", "..", "fixtures", "debug-data.json")
	}
	if dataPath != "" {
		cfg.DebugDataPath = dataPath
	}

	return cfg, nil
}

func main() {
	cfg, err := NewDebugConfig()
	if err != nil {
		log.Fatal("failed to debug load config", "error", err)
	}
	log.SetLevel(cfg.AppLogLevel)

	s, err := sender.NewSender(context.Background(), cfg)
	if err != nil {
		log.Fatal("failed to init sender", "error", err)
	}

	data, err := os.ReadFile(cfg.DebugDataPath)
	if err != nil {
		log.Fatal("failed to read data file", "path", dataPath, "error", err)
	}

	events := []aws.CognitoEventUserPoolsCustomEmailSender{}
	if err := json.Unmarshal(data, &events); err != nil {
		log.Fatal("failed to parse event file", "error", err)
	}

	for i, e := range events {
		if err := s.SendEmail(context.Background(), e); err != nil {
			log.Error("integration test failed", "error", err)
			os.Exit(1)
		}
		log.Info("integration iteration passed", "index", i)
	}

	log.Info("integration test passed")
}
