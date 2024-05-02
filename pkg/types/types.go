package types

import (
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

type EntryTask struct {
	Entries *ct.GetEntriesResponse
	Index   int64
}
