package ipapi

import (
	"testing"
)

func TestGetIP(t *testing.T) {
	_, err := GetIpInfo()
	if err != nil {
		t.Error(err)
		return
	}
}
