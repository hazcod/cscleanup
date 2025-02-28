package falcon

import "time"

type Host struct {
	ID              string
	Hostname        string
	OperatingSystem string
	Tags            []string
	ServiceProvider string
	LastSeen        time.Time
	MacAddress      string
}
