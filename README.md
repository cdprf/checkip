[![Build Status](https://travis-ci.org/jreisinger/checkip.svg?branch=master)](https://travis-ci.org/jreisinger/checkip)

# checkip

`checkip` is a CLI tool that finds out information about an IP address (the output is colored in [real terminal](https://reisinge.net/blog/2021-01-15-check-ip-address)):

```
$ checkip 45.155.205.108
AS          49505, 45.155.205.0 - 45.155.205.255, SELECTEL
AbuseIPDB   reported abusive 2808 times with 100% confidence (smartdata.su)
DNS         lookup 45.155.205.108: nodename nor servname provided, or not known
Geolocation St Petersburg, Russia, RU
IPsum       found on 3 blacklists
OTX         threat score 2 (seen 2020-12-23 - 2021-02-03)
Shodan      OS unknown, open ports: 123 (service unknown, version unknown)
ThreatCrowd voted malicious/harmless by equal number of users
VirusTotal  71 harmless, 0 suspicious, 7 malicious analysis results

# Three checks say the IP address is not OK.
$ echo $?
3

# Run only selected checks.
$ checkip -check dns,ipsum 1.1.1.1
DNS         one.one.one.one.
IPsum       found on 0 blacklists
```

## Installation

Download the latest [release](https://github.com/jreisinger/checkip/releases)
for your operating system and architecture. Copy it to your `bin` folder (or
some other folder on your `PATH`) and make it executable.

The same spelled out in Bash:

```
export SYS=linux # or darwin
export ARCH=amd64
export REPO=checkip
export REPOURL=https://github.com/jreisinger/$REPO
curl -L $REPOURL/releases/latest/download/$REPO-$SYS-$ARCH -o $HOME/bin/$REPO
chmod u+x $HOME/bin/$REPO
```

## Config File

For some checks (see below) to work you need to register and get a
LICENSE/API key. Then create a `$HOME/.checkip.yaml` using your editor of
choice. Provide your API/license keys using the following template:

```
ABUSEIPDB_API_KEY: aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff11111111222222223333333344444444
GEOIP_LICENSE_KEY: abcdef1234567890
VIRUSTOTAL_API_KEY: aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff1111111122222222
SHODAN_API_KEY: aaaabbbbccccddddeeeeffff11112222
```

You can also use environment variables with the same names as in the config file.

## Features

* Easy to install since it's a single binary.
* Files necessary for some checks are automatically downloaded and updated in the background.
* Checks are done concurrently to save time.
* Output is colored to improve readability.
* You can select which checks you want to run.
* Return non-zero exit code when one or more checks say the IP address is not OK.
* It's easy to add new checks.

Currently these checks (types of information) are available:

* AS (Autonomous System) data using TSV file from [iptoasn](https://iptoasn.com/).
* [AbuseIPDB](https://www.abuseipdb.com) reports that the IP address is malicious. You need to [register](https://www.abuseipdb.com/register?plan=free) to get the API key (it's free).
* DNS names using [net.LookupAddr](https://golang.org/pkg/net/#LookupAddr) Go function.
* Geographic location using [GeoLite2 City database](https://dev.maxmind.com/geoip/geoip2/geolite2/) file. You need to [register](https://dev.maxmind.com/geoip/geoip2/geolite2/#Download_Access) to get the license key (it's free).
* Blacklists the IP address is found on according to [IPsum](https://github.com/stamparm/ipsum) file.
* Threat score from [OTX](https://otx.alienvault.com/).
* [Shodan](https://www.shodan.io/) scan data. You need to [register](https://account.shodan.io/register) to get the API key (it's free).
* [ThreatCrowd](https://www.threatcrowd.org/) voting about whether the IP address is malicious.
* [VirusTotal](https://developers.virustotal.com/v3.0/reference#ip-object) analysis results. You need to [register](https://www.virustotal.com/gui/join-us) to to get the API key (it's free).

## Development

```
vim main.go
make install # version defaults to "dev" if VERSION envvar is not set
```

When you push to GitHub Travis CI will try and build a release for you and
publish it on GitHub. Builds are done inside Docker container. To build a
release locally:

```
make release
```

Check test coverage:

```
go test -coverprofile cover.out ./...
go tool cover -html=cover.out
```
