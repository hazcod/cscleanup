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

func withinFiveMinutes(t1, t2 time.Time) bool {
	diff := t1.Sub(t2)
	if diff < 0 {
		diff = -diff
	}
	return diff <= 5*time.Minute
}

func (c *CS) getHiddenHosts() ([]*models.DeviceapiDeviceSwagger, error) {
	allHostDetails := make([]*models.DeviceapiDeviceSwagger, 0)

	c.logger.Debug("retrieving hidden hosts")

	round := 0
	offset := int64(0)

	sort := `last_seen.desc`

	for {
		resp, err := c.client.Hosts.QueryHiddenDevices(&hosts.QueryHiddenDevicesParams{
			Filter:  nil,
			Limit:   &csMaxQueryLimit,
			Offset:  &offset,
			Sort:    &sort,
			Context: c.ctx,
		})

		if err != nil || resp == nil || !resp.IsSuccess() {
			return nil, fmt.Errorf("response error: %v -> %+v", err, resp)
		}

		hostIDs := resp.GetPayload().Resources

		c.logger.WithField("host_ids", len(hostIDs)).WithField("round", round).
			Debug("retrieving hidden host details")

		for i := 0; i < len(hostIDs); i += csDetailsFetchSize {
			end := i + csDetailsFetchSize
			if end > len(hostIDs) {
				end = len(hostIDs)
			}

			c.logger.WithField("slice_start", i).WithField("slice_end", end).
				Debug("fetching hidden host device details")

			slicePart := hostIDs[i:end]

			hostDetail, err := c.client.Hosts.GetDeviceDetailsV2(&hosts.GetDeviceDetailsV2Params{
				Ids:     slicePart,
				Context: c.ctx,
			})
			if err != nil || !hostDetail.IsSuccess() {
				return nil, fmt.Errorf("could not query all hidden host details: %v", err)
			}

			allHostDetails = append(allHostDetails, hostDetail.GetPayload().Resources...)

			c.logger.WithField("slice_start", i).WithField("slice_end", end).Trace("fetched hidden")
		}

		// Stop pagination if we reached the end
		isLast, err := resp.GetPayload().Meta.Pagination.LastPage()
		if err != nil {
			return nil, fmt.Errorf("could not get pagination last page: %v\n", err)
		}

		if isLast {
			if int64(len(allHostDetails)) != *resp.GetPayload().Meta.Pagination.Total {
				return nil, fmt.Errorf("pagination total does not match pagination: fetched %d != total %d \n",
					len(allHostDetails), *resp.GetPayload().Meta.Pagination.Total)
			}

			// stop paging, we reached the end
			break
		}

		round += 1
		offset += int64(len(resp.GetPayload().Resources))
	}

	c.logger.WithField("total_details", len(allHostDetails)).
		Debug("fetched host details")

	return allHostDetails, nil
}

func (c *CS) getAllHostDetails() ([]*models.DeviceapiDeviceSwagger, error) {
	allHostDetails := make([]*models.DeviceapiDeviceSwagger, 0)

	c.logger.Debug("retrieving clients")

	round := 0
	offset := int64(0)

	sort := `last_seen.desc`
	for {
		resp, err := c.client.Hosts.QueryDevicesByFilter(&hosts.QueryDevicesByFilterParams{
			Filter:  nil,
			Limit:   &csMaxQueryLimit,
			Offset:  &offset,
			Sort:    &sort,
			Context: c.ctx,
		})

		if err != nil || resp == nil || !resp.IsSuccess() {
			return nil, fmt.Errorf("response error: %v -> %+v", err, resp)
		}

		hostIDs := resp.GetPayload().Resources

		c.logger.WithField("host_ids", len(hostIDs)).WithField("round", round).
			Debug("retrieving host details")

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
				return nil, fmt.Errorf("could not query all host details: %v", err)
			}

			allHostDetails = append(allHostDetails, hostDetail.GetPayload().Resources...)

			c.logger.WithField("slice_start", i).WithField("slice_end", end).Trace("fetched")
		}

		// Stop pagination if we reached the end
		isLast, err := resp.GetPayload().Meta.Pagination.LastPage()
		if err != nil {
			return nil, fmt.Errorf("could not get pagination last page: %v\n", err)
		}

		if isLast {
			if int64(len(allHostDetails)) != *resp.GetPayload().Meta.Pagination.Total {
				return nil, fmt.Errorf("pagination total does not match pagination: fetched %d != total %d \n",
					len(allHostDetails), *resp.GetPayload().Meta.Pagination.Total)
			}

			// stop paging, we reached the end
			break
		}

		round += 1
		offset += int64(len(resp.GetPayload().Resources))
	}

	c.logger.WithField("total_details", len(allHostDetails)).
		Debug("fetched host details")

	return allHostDetails, nil
}

func hasTag(device *models.DeviceapiDeviceSwagger) bool {
	for _, tag := range device.Tags {
		if strings.Contains(strings.ToLower(tag), "email/") {
			return true
		}
	}

	return false
}

func isCloudHost(device *models.DeviceapiDeviceSwagger) bool {
	return device.ServiceProvider != "" || strings.EqualFold(device.ProductTypeDesc, "Pod")
}

func isRFM(device *models.DeviceapiDeviceSwagger) bool {
	return strings.EqualFold(device.ReducedFunctionalityMode, "yes")
}

func (c *CS) CleanupClients() (untagged, rfm, wronglyHidden, toDelete []Host, err error) {

	allHostDetails, err := c.getAllHostDetails()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not query all hosts: %w", err)
	}

	hiddenHosts, err := c.getHiddenHosts()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("could not query hidden hosts: %w", err)
	}

	last24h := time.Now().Add(-time.Hour * 24)

	for _, host := range allHostDetails {
		alreadyHasTag := hasTag(host)

		hostLastSeen, err := time.Parse("2006-01-02T15:04:05Z", host.LastSeen)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("could not parse last seen time: %v", err)
		}

		hostFirstSeen, err := time.Parse("2006-01-02T15:04:05Z", host.FirstSeen)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("could not parse first seen time: %v", err)
		}

		// check for empty cloud hosts that were online too short to be functional
		if !alreadyHasTag && host.Hostname == "" && len(host.Policies) == 0 {
			host.Hostname = *host.DeviceID

			checkDate := time.Now().Add(-time.Hour * 2)
			if withinFiveMinutes(hostFirstSeen, hostLastSeen) && hostLastSeen.Before(checkDate) {
				c.logger.WithField("host_id", *host.DeviceID).Warn("deleting empty temporary host")
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

		// check for user endpoint sensors that are not tagged
		if !isCloudHost(host) && !alreadyHasTag {
			if host.Hostname == "" {
				host.Hostname = *host.DeviceID
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

		// check for any sensor in RFM mode
		if isRFM(host) && hostLastSeen.After(last24h) {
			c.logger.WithField("rfm", host.ReducedFunctionalityMode).
				WithField("id", *host.DeviceID).
				WithField("hostname", host.Hostname).
				Trace("found rfm host")

			rfm = append(rfm, Host{
				ID:              *host.DeviceID,
				Hostname:        host.Hostname,
				OperatingSystem: host.OsProductName,
				LastSeen:        hostLastSeen,
				Tags:            host.Tags,
				ServiceProvider: host.ServiceProvider,
			})
		}

		//  check for cloud hosts which were offline for some while
		if isCloudHost(host) && hostLastSeen.Before(last24h) {

			c.logger.WithField("id", *host.DeviceID).WithField("last_seen", hostLastSeen.Format(time.DateTime)).
				WithField("hostname", host.Hostname).
				Debug("can delete offline cloud host")

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

	for _, host := range hiddenHosts {
		hostLastSeen, err := time.Parse("2006-01-02T15:04:05Z", host.LastSeen)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("could not parse last seen time: %v", err)
		}

		if hostLastSeen.After(last24h) {
			c.logger.WithField("rfm", host.ReducedFunctionalityMode).
				WithField("id", *host.DeviceID).
				WithField("hostname", host.Hostname).
				WithField("hidden_status", host.HostHiddenStatus).
				WithField("tags", &host.Tags).
				Warn("found hidden host which was recently seen!")

			wronglyHidden = append(wronglyHidden, Host{
				ID:              *host.DeviceID,
				Hostname:        host.Hostname,
				OperatingSystem: host.OsProductName,
				LastSeen:        hostLastSeen,
				Tags:            host.Tags,
				ServiceProvider: host.ServiceProvider,
			})
		}
	}

	return untagged, rfm, wronglyHidden, toDelete, nil
}
