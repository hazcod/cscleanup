package falcon

import (
	"context"
	"fmt"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
)

const (
	csMaxDeleteLimit = 100
)

func (c *CS) hideClientsPaged(hostIDs []string) error {
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

	return nil
}

func (c *CS) HideClients(hostIDs []string) error {
	c.logger.WithField("hosts", len(hostIDs)).Debug("deleting clients")

	if len(hostIDs) == 0 {
		return fmt.Errorf("no hosts to delete")
	}

	total := len(hostIDs)
	checkTotal := 0

	for i := 0; i < len(hostIDs); i += csMaxDeleteLimit {
		end := i + csMaxDeleteLimit

		// Ensure the end index does not exceed the slice's length
		if end > len(hostIDs) {
			end = len(hostIDs)
		}

		subSlice := hostIDs[i:end]

		checkTotal += len(subSlice)

		c.logger.WithField("step", fmt.Sprintf("%d", i)).Debug("hiding hosts")

		if err := c.hideClientsPaged(subSlice); err != nil {
			return err
		}
	}

	if total != checkTotal {
		return fmt.Errorf("didn't delete enough hosts, total %d != checkTotal %d", total, checkTotal)
	}

	c.logger.WithField("hosts", len(hostIDs)).Debug("deleted hosts")

	return nil
}
