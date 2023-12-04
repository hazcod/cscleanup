package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hazcod/cscleanup/config"
	"github.com/hazcod/cscleanup/pkg/falcon"
	"github.com/sirupsen/logrus"
	"net/http"
	"time"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	ctx := context.Background()

	confFile := flag.String("config", "", "The YAML configuration file.")
	flag.Parse()

	conf := config.Config{}
	if err := conf.Load(logger, *confFile); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("failed to load configuration")
	}

	if err := conf.Validate(); err != nil {
		logger.WithError(err).WithField("config", *confFile).Fatal("invalid configuration")
	}

	logrusLevel, err := logrus.ParseLevel(conf.Log.Level)
	if err != nil {
		logger.WithError(err).Error("invalid log level provided")
		logrusLevel = logrus.InfoLevel
	}
	logger.SetLevel(logrusLevel)

	// --

	crowdstrike, err := falcon.New(logger, ctx, conf.CrowdStrike)
	if err != nil {
		logger.WithError(err).Fatal("failed to load crowdstrike module")
	}

	untaggedClients, rfmClients, toDeleteHosts, err := crowdstrike.GetUntaggedClients()
	if err != nil {
		logger.WithError(err).Fatal("could not fetch untagged clients")
	}

	// ---

	overviewText := ""

	overviewText += "-- CrowdStrike host overview\n\n"

	overviewText += "\n> Untagged hosts:\n"
	for _, host := range untaggedClients {
		if host.ServiceProvider != "" {
			continue
		}

		overviewText += fmt.Sprintf("- %s (%s, %s, %s, %s)\n",
			host.Hostname, host.OperatingSystem, host.LastSeen, host.Tags, host.ServiceProvider)
	}

	overviewText += "\n> Inactive hosts:\n"
	minAliveDate := time.Now().Add(-1 * time.Hour * 24 * 60) // two months
	for _, host := range untaggedClients {
		if host.LastSeen.After(minAliveDate) {
			continue
		}

		overviewText += fmt.Sprintf("- %s (%s, %s, %s, %s)\n",
			host.Hostname, host.OperatingSystem, host.LastSeen, host.Tags, host.ServiceProvider)
	}

	overviewText += "\n> RFM/broken hosts:\n"
	for _, host := range rfmClients {
		overviewText += fmt.Sprintf("- %s (%s, %s, %s, %s)\n",
			host.Hostname, host.OperatingSystem, host.LastSeen, host.Tags, host.ServiceProvider)
	}

	overviewText += "\n> Cloud hosts being cleaned up:\n"
	var deleteHostIDs []string
	for _, host := range toDeleteHosts {
		deleteHostIDs = append(deleteHostIDs, host.ID)
		overviewText += fmt.Sprintf("- %s (%s, %s, %s, %s)\n",
			host.Hostname, host.OperatingSystem, host.LastSeen, host.Tags, host.ServiceProvider)
	}

	if len(deleteHostIDs) > 0 {
		if err := crowdstrike.HideClients(deleteHostIDs); err != nil {
			logger.WithError(err).Fatal("could not delete clients")
		}
	}

	logger.Info(overviewText)

	// ---

	slackMsg := struct {
		Text string `json:"text"`
	}{
		Text: overviewText,
	}

	data, err := json.Marshal(slackMsg)
	if err != nil {
		logger.WithError(err).Fatal("failed to marshal slack message")
	}
	logrus.Fatal()
	body := bytes.NewReader(data)
	resp, err := http.Post(conf.Slack.WebhookURL, "application/json", body)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		logrus.WithError(err).Fatal("failed to send to slack")
	}

	logger.Debug("finished")
}
