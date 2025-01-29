package models

type Connection struct {
	ID    string `gorm:"primaryKey" json:"ID"`
	Src   string `json:"Src,omitempty"`
	Dst   string `json:"Dst,omitempty"`
	Port  int    `json:"Port,omitempty"`
    Count float64    `json:"Count,omitempty"`
}

type Agent struct {
    ID       string `gorm:"primaryKey"`
    Hostname string
    HostOS   string
    IP       string
    Status   string
}
