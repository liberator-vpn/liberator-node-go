package ipapi

import (
	"encoding/json"
	"net/http"
)

/*
	{
		"status":"success",
		"country":"Finland",
		"countryCode":"FI",
		"region":"18",
		"regionName":"Uusimaa",
		"city":"Helsinki",
		"zip":"00201",
		"lat":60.1719,
		"lon":24.9347,
		"timezone":"Europe/Helsinki",
		"isp":"Chsl ONE LTD",
		"org":"CHSL Helsinki",
		"as":"AS210546 CHSL ONE LTD",
		"query":"144.31.133.121"
	}
*/
type IpInfo struct {
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"region"`
	RegionName  string  `json:"regionName"`
	City        string  `json:"city"`
	Zip         string  `json:"zip"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Isp         string  `json:"isp"`
	Org         string  `json:"org"`
	As          string  `json:"as"`
	Query       string  `json:"query"`
}

func GetIpInfo() (*IpInfo, error) {
	rq, err := http.NewRequest(http.MethodGet, "http://ip-api.com/json", nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{}

	resp, err := client.Do(rq)
	if err != nil {
		return nil, err
	}

	var ipInfo IpInfo

	if err = json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return nil, err
	}
	return &ipInfo, nil
}
