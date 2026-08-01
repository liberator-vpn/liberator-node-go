package model

type ConnectivityState struct {
	Id        string `json:"id"`
	Addr      string `json:"addr"`
	TotalSent uint64 `json:"total_sent"`
	TotalRecv uint64 `json:"total_recv"`
	// TODO: PING
}
