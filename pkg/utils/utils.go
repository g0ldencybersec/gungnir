package utils

import (
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

	"filippo.io/sunlight"
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
func createLogClient(key []byte, url string) (*client.LogClient, error) {
	pemPK := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: key,
	})
	opts := jsonclient.Options{PublicKey: string(pemPK), UserAgent: "gungnir-" + uuid.New().String()}
	c, err := client.New(url, &http.Client{
		Timeout: 27 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, opts)
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
		CommonName:   cert.Subject.CommonName,
		Organization: cert.Subject.Organization,
		SAN:          cert.DNSNames,
		Domains:      append([]string{cert.Subject.CommonName}, cert.DNSNames...),
		Source:       "rfc6962",
	}
	outputJson, _ := json.Marshal(certInfo)
	fmt.Println(string(outputJson))
}

// Static CT Log types for parsing the log list JSON
type StaticLogList struct {
	Operators []StaticOperator `json:"operators"`
}

type StaticOperator struct {
	Name      string           `json:"name"`
	Logs      []StaticLogEntry `json:"logs"`
	TiledLogs []StaticLogEntry `json:"tiled_logs"`
}

type StaticLogEntry struct {
	Description   string `json:"description"`
	LogID         string `json:"log_id"`
	MonitoringURL string `json:"monitoring_url"`
	SubmissionURL string `json:"submission_url"`
	URL           string `json:"url"`
	Key           string `json:"key"`
}

// staticHttpClient is a shared HTTP client for static CT log operations
var staticHttpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       30 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		MaxConnsPerHost:       100,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

// PopulateStaticLogs parses the log list and returns static/tiled CT logs
func PopulateStaticLogs(logListURL string) ([]types.StaticCtLog, error) {
	u, err := url.Parse(logListURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	body, err := readURL(u)
	if err != nil {
		return nil, fmt.Errorf("failed to get log list data: %v", err)
	}

	var logList StaticLogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	var logs []types.StaticCtLog
	for _, operator := range logList.Operators {
		for _, log := range operator.TiledLogs {
			// Skip logs without monitoring URL
			if log.MonitoringURL == "" {
				continue
			}

			client, err := sunlight.NewClient(&sunlight.ClientConfig{
				MonitoringPrefix: log.MonitoringURL,
				HTTPClient:       staticHttpClient,
				UserAgent:        "gungnir +https://github.com/g0ldencybersec/gungnir",
			})
			if err != nil {
				// Log error but continue with other logs
				fmt.Fprintf(os.Stderr, "Failed to create static log client for %s: %v\n", log.Description, err)
				continue
			}

			l := types.StaticCtLog{
				Id:            log.LogID,
				Name:          log.Description,
				MonitoringURL: log.MonitoringURL,
				Client:        client,
			}
			logs = append(logs, l)
		}
	}

	return logs, nil
}
