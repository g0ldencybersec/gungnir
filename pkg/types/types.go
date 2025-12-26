package types

import (
	"filippo.io/sunlight"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
)

// ctLog contains the latest witnessed STH for a log and a log client.
type CtLog struct {
	Id     string
	Name   string
	Wsth   *ct.SignedTreeHead
	Client *client.LogClient
}

// StaticCtLog contains info for a static/tiled CT log using the sunlight library.
type StaticCtLog struct {
	Id            string
	Name          string
	MonitoringURL string
	Client        *sunlight.Client
}

type EntryTask struct {
	Entries *ct.GetEntriesResponse
	Index   int64
}

// Result Types
type CertificateInfo struct {
	CommonName   string   `json:"commonName"`
	Organization []string `json:"org"`
	SAN          []string `json:"san"`
	Domains      []string `json:"domains"`
	Source       string   `json:"source"`
}

type GungnirMessage struct {
	Domain string
}
