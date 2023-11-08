package config

import (
	"fmt"
	validator "github.com/asaskevich/govalidator"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"os"
)

const (
	defaultLogLevel = "INFO"
)

type CrowdStrike struct {
	Region string `yaml:"region"`

	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type Slack struct {
	WebhookURL string `yaml:"webhook"`
}

type Config struct {
	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`

	CrowdStrike CrowdStrike `yaml:"crowdstrike"`
	Slack       Slack       `yaml:"slack"`
}

func (c *Config) Validate() error {
	if c.Log.Level == "" {
		c.Log.Level = defaultLogLevel
	}

	if c.Slack.WebhookURL == "" {
		return fmt.Errorf("no Slack webhook provided")
	}

	if c.CrowdStrike.ClientID == "" || c.CrowdStrike.ClientSecret == "" {
		return fmt.Errorf("no CrowdStrike API credentials provided")
	}

	if valid, err := validator.ValidateStruct(c); !valid || err != nil {
		return fmt.Errorf("invalid configuration: %v", err)
	}

	return nil
}

func (c *Config) Load(l *logrus.Logger, path string) error {
	if path != "" {
		l.WithField("config", path).Info("loading configuration file")

		configBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to load configuration file at '%s': %v", path, err)
		}

		if err = yaml.Unmarshal(configBytes, c); err != nil {
			return fmt.Errorf("failed to parse configuration: %v", err)
		}
	} else {
		l.Info("no config file provided, loading from environemnt variables")
	}

	if err := envconfig.Process("CSC", c); err != nil {
		return fmt.Errorf("could not load environment: %v", err)
	}

	return nil
}
