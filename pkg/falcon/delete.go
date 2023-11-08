package falcon

import (
	"context"
	"fmt"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

const (
	csMaxDeleteLimit = 5000
)

func (c *CS) DeleteClients(hostIDs []string) error {
	c.logger.WithField("hosts", len(hostIDs)).Debug("deleting clients")

	if len(hostIDs) == 0 {
		return fmt.Errorf("no hosts to delete")
	}

	if len(hostIDs) > csMaxDeleteLimit {
		return fmt.Errorf("cannot delete more than 5000 hosts at once")
	}

	resp, err := c.client.Hosts.PerformActionV2(&hosts.PerformActionV2Params{
		ActionName: "hide_host",
		Body: &models.MsaEntityActionRequestV2{
			Ids: hostIDs,
		},
		Context:    context.Background(),
		HTTPClient: nil,
	})

	if err != nil || resp == nil || !resp.IsSuccess() {
		return fmt.Errorf("response error: %v -> %+v", err, resp)
	}

	c.logger.WithField("hosts", len(hostIDs)).Debug("deleted hosts")

	return nil
}
