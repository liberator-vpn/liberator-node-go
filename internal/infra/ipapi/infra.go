package ipapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const ipInfoURL = "https://ipinfo.io/json"

type IPInfo struct {
	IP          string `json:"ip"`
	City        string `json:"city"`
	Region      string `json:"region"`
	CountryCode string `json:"country"`
	Loc         string `json:"loc"`
	Org         string `json:"org"`
	Postal      string `json:"postal"`
	Timezone    string `json:"timezone"`
	Readme      string `json:"readme"`
}

func GetIpInfo(ctx context.Context) (*IPInfo, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return getIpInfo(ctx, client, ipInfoURL)
}

func getIpInfo(ctx context.Context, client *http.Client, url string) (*IPInfo, error) {
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

	var ipInfo IPInfo

	if err := json.NewDecoder(resp.Body).Decode(&ipInfo); err != nil {
		return nil, err
	}
	return &ipInfo, nil
}
