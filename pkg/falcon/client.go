package falcon

import (
	"context"
	"fmt"
	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/hazcod/cscleanup/config"
	"github.com/sirupsen/logrus"
)

type CS struct {
	logger *logrus.Logger
	client *client.CrowdStrikeAPISpecification
	ctx    context.Context
}

func New(logger *logrus.Logger, ctx context.Context, config config.CrowdStrike) (CS, error) {
	if logger == nil {
		return CS{}, fmt.Errorf("invalid logger supplied")
	}

	cs := CS{
		logger: logger,
		ctx:    ctx,
	}

	csCloud, err := falcon.CloudValidate(config.Region)
	if err != nil {
		return CS{}, fmt.Errorf("invalid region: %v", err)
	}

	csClient, err := falcon.NewClient(&falcon.ApiConfig{
		ClientId:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Context:      ctx,
		Cloud:        csCloud,
	})
	if err != nil || csClient == nil {
		return CS{}, fmt.Errorf("failed to create client: %v", err)
	}

	cs.client = csClient

	return cs, nil
}
