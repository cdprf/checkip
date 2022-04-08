package check

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/jreisinger/checkip"
	"github.com/oschwald/geoip2-golang"
)

type maxmind struct {
	City    string `json:"city"`
	Country string `json:"country"`
	IsoCode string `json:"iso_code"`
	IsInEU  bool   `json:"is_in_eu"`
}

func (m maxmind) Summary() string {
	return fmt.Sprintf("country: %s (%s), city: %s, EU member: %t",
		checkip.Na(m.Country), checkip.Na(m.IsoCode), checkip.Na(m.City), m.IsInEU)
}

func (m maxmind) JsonString() (string, error) {
	b, err := json.Marshal(m)
	return string(b), err
}

// MaxMind gets geolocation data from maxmind.com's GeoLite2-City.mmdb.
func MaxMind(ip net.IP) (checkip.Result, error) {
	result := checkip.Result{
		Name: "maxmind.com",
		Type: checkip.TypeInfo,
	}

	licenseKey, err := checkip.GetConfigValue("MAXMIND_LICENSE_KEY")
	if err != nil {
		return result, checkip.NewError(err)
	}
	if licenseKey == "" {
		return result, nil
	}

	file := "/var/tmp/GeoLite2-City.mmdb"
	url := "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=" + licenseKey + "&suffix=tar.gz"

	if err := checkip.UpdateFile(file, url, "tgz"); err != nil {
		return result, checkip.NewError(err)
	}

	db, err := geoip2.Open(file)
	if err != nil {
		return result, checkip.NewError(fmt.Errorf("can't load DB file: %v", err))
	}
	defer db.Close()

	geo, err := db.City(ip)
	if err != nil {
		return result, checkip.NewError(err)
	}

	result.Info = maxmind{
		City:    geo.City.Names["en"],
		Country: geo.Country.Names["en"],
		IsoCode: geo.Country.IsoCode,
		IsInEU:  geo.Country.IsInEuropeanUnion,
	}

	return result, nil
}