# cscleanup

A Go program that cleans up your estate of CrowdStrike cloud and endpoint sensors.

## How does it work?

The program follows following logic for determining if a sensor is faulty and shrouds your dashboard:

1. Any CrowdStrike sensor that was only momentarily online (max. 5 minutes), did not have the chance to donwload any policies and did not report a Hostname.
2. Any CrowdStrike endpoint sensor that does not have an `email/` tag. (e.g. to use with [security-slacker](https://github.com/hazcod/security-slacker/))
3. Any CrowdStrike sensor that is in RFM mode and was last seen over 24 hours ago.
4. Any CrowdStrike cloud sensor that has not been seen for 24 hours. (VMs were most likely destroyed)
5. Any hidden CrowdStrike sensor that was still recently seen, e.g. was most likely hidden by accident.

## Running

First, ensure you get CrowdStrike API credentials that can do `Hosts:read` and `Hosts:write`.
Then create the following YAML configuration file:

```yaml
log:
  level: INFO

slack:
  webhook: "https://hooks.slack.com/services/XXX"

crowdstrike:
  region: eu-1
  client_id: "XXXX"
  client_secret: "XXXX"

```

You can use following arguments:

```shell
./cscleanup -config=config.yml
```

And if you don't want to hide any sensor nor send to Slack:

```shell
./cscleanup -config=config.yml -preview
```
