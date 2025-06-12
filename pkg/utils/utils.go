package utils

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/g0ldencybersec/gungnir/pkg/types"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/uuid"

	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
)

var getByScheme = map[string]func(*url.URL) ([]byte, error){
	"http":  readHTTP,
	"https": readHTTP,
	"file": func(u *url.URL) ([]byte, error) {
		return os.ReadFile(u.Path)
	},
}

// readHTTP fetches and reads data from an HTTP-based URL.
func readHTTP(u *url.URL) ([]byte, error) {
	resp, err := http.Get(u.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func readURL(u *url.URL) ([]byte, error) {
	s := u.Scheme
	queryFn, ok := getByScheme[s]
	if !ok {
		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
	}
	return queryFn(u)
}

// createLogClient creates a CT log client from a public key and URL.
// FIXED: Only adds HTTP/2 deadlock prevention while preserving all original settings
func createLogClient(key []byte, url string) (*client.LogClient, error) {
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK), UserAgent: "gungnir-" + uuid.New().String()}
	
	// CRITICAL FIX: Create HTTP transport that prevents HTTP/2 deadlock
	// All original timeout and connection values preserved exactly
	transport := &http.Transport{
		// ONLY CHANGE: Disable HTTP/2 to prevent context cancellation deadlock
		TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
		
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableKeepAlives:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	
	httpClient := &http.Client{
		Timeout:   27 * time.Second,
		Transport: transport,
	}
	
	c, err := client.New(url, httpClient, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create JSON client: %v", err)
	}
	return c, nil
}

func PopulateLogs(logListURL string) ([]types.CtLog, error) {
	u, err := url.Parse(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get log list data: %v", err)
	}
	// Get data for all usable logs.
	logList, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}
	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus, loglist3.PendingLogStatus, loglist3.ReadOnlyLogStatus, loglist3.QualifiedLogStatus, loglist3.RetiredLogStatus})
	var logs []types.CtLog
	for _, operator := range usable.Operators {
		for _, log := range operator.Logs {
			logID := base64.StdEncoding.EncodeToString(log.LogID)
			c, err := createLogClient(log.Key, log.URL)
			if err != nil {
				return nil, fmt.Errorf("failed to create log client: %v", err)
			}
			l := types.CtLog{
				Id:     logID,
				Name:   log.Description,
				Client: c,
			}
			logs = append(logs, l)
		}
	}
	return logs, nil
}

// Checks if a domain is a subdomain of any root domain in the global map
func IsSubdomain(domain string, rootDomains map[string]bool) bool {
	if _, ok := rootDomains[domain]; ok {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := range parts {
		parentDomain := strings.Join(parts[i:], ".")
		if _, ok := rootDomains[parentDomain]; ok {
			return true
		}
	}

	return false
}

func JsonOutput(cert *x509.Certificate) {
	certInfo := types.CertificateInfo{
		OriginIP:         "",
		Organization:     cert.Subject.Organization,
		OrganizationUnit: cert.Subject.OrganizationalUnit,
		CommonName:       cert.Subject.CommonName,
		SAN:              cert.DNSNames,
		Domains:          append([]string{cert.Subject.CommonName}, cert.DNSNames...),
		Emails:           cert.EmailAddresses,
		IPAddrs:          cert.IPAddresses,
	}
	outputJson, _ := json.Marshal(certInfo)
	fmt.Println(string(outputJson))
}
