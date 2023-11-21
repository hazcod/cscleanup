package falcon

import (
	"fmt"
	"github.com/crowdstrike/gofalcon/falcon/client/hosts"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"strings"
	"time"
)

var (
	csMaxQueryLimit    = int64(5000)
	csDetailsFetchSize = 100
)

func (c *CS) GetUntaggedClients() (untagged []Host, rfm []Host, toDelete []Host, err error) {
	c.logger.Debug("retrieving untagged clients")

	sort := `last_seen.desc`
	resp, err := c.client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
		// unable to filter since crowdstrike doesn't support filtering on partial tags
		Filter:  nil,
		Limit:   &csMaxQueryLimit,
		Offset:  nil,
		Sort:    &sort,
		Context: c.ctx,
	})

	if err != nil || resp == nil || !resp.IsSuccess() {
		return nil, nil, nil, fmt.Errorf("response error: %v -> %+v", err, resp)
	}

	hostIDs := resp.GetPayload().Resources

	c.logger.WithField("host_ids", len(hostIDs)).Debug("retrieving host details")

	allHostDetails := make([]*models.DeviceapiDeviceSwagger, 0)

	for i := 0; i < len(hostIDs); i += csDetailsFetchSize {
		end := i + csDetailsFetchSize
		if end > len(hostIDs) {
			end = len(hostIDs)
		}

		c.logger.WithField("slice_start", i).WithField("slice_end", end).
			Debug("fetching host device details")

		slicePart := hostIDs[i:end]

		hostDetail, err := c.client.Hosts.GetDeviceDetailsV2(&hosts.GetDeviceDetailsV2Params{
			Ids:     slicePart,
			Context: c.ctx,
		})
		if err != nil || !hostDetail.IsSuccess() {
			return nil, nil, nil, fmt.Errorf("could not query all host details: %v", err)
		}

		allHostDetails = append(allHostDetails, hostDetail.GetPayload().Resources...)

		c.logger.WithField("slice_start", i).WithField("slice_end", end).Trace("fetched")
	}

	c.logger.WithField("total_details", len(allHostDetails)).
		WithField("total_hosts", len(hostIDs)).
		Debug("fetched host details")

	for _, host := range allHostDetails {
		alreadyHasTag := false

		for _, tag := range host.Tags {
			if strings.Contains(strings.ToLower(tag), "email/") {
				alreadyHasTag = true
				break
			}
		}

		hostLastSeen, err := time.Parse("2006-01-02T15:04:05Z", host.LastSeen)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("could not parse last seen time: %v", err)
		}

		if !alreadyHasTag {
			// don't log untagged cloud hosts
			if host.ServiceProvider != "" {
				continue
			}

			// skip hosts without a hostname (probably a host not yet fully deployed)
			if host.Hostname == "" {
				c.logger.WithField("id", *host.DeviceID).Warn("no hostname for host")
				continue
			}

			untagged = append(untagged, Host{
				ID:              *host.DeviceID,
				Hostname:        host.Hostname,
				OperatingSystem: host.OsProductName,
				LastSeen:        hostLastSeen,
				Tags:            host.Tags,
				ServiceProvider: host.ServiceProvider,
			})
		}

		// --

		if host.ReducedFunctionalityMode != "no" && host.ReducedFunctionalityMode != "Unknown" {
			rfm = append(rfm, Host{
				ID:              *host.DeviceID,
				Hostname:        host.Hostname,
				OperatingSystem: host.OsProductName,
				LastSeen:        hostLastSeen,
				Tags:            host.Tags,
				ServiceProvider: host.ServiceProvider,
			})
		}

		// --
		checkDate := time.Now().Add(-time.Hour * 24 /**/)
		if host.ServiceProvider != "" && hostLastSeen.Before(checkDate) {
			c.logger.WithField("id", *host.DeviceID).Debug("can delete cloud host")

			toDelete = append(toDelete, Host{
				ID:              *host.DeviceID,
				Hostname:        host.Hostname,
				OperatingSystem: host.OsProductName,
				LastSeen:        hostLastSeen,
				Tags:            host.Tags,
				ServiceProvider: host.ServiceProvider,
			})
		}
	}

	return untagged, rfm, toDelete, nil
}
