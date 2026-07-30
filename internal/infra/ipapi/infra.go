package ipapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const ipInfoURL = "http://ip-api.com/json"

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

func GetIpInfo(ctx context.Context) (*IpInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return getIpInfo(ctx, client, ipInfoURL)
}

func getIpInfo(ctx context.Context, client *http.Client, url string) (*IpInfo, error) {
	rq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(rq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("IP API returned %s", resp.Status)
	}

	var ipInfo IpInfo

	if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return nil, err
	}
	return &ipInfo, nil
}
