package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

type LogsList struct {
	Operators []struct {
		Logs []struct {
			URL string `json:"url"`
		} `json:"logs"`
	} `json:"operators"`
}

var (
	logListUrl = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"

	matchSubjectRegex = `^(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|localhost)$` // Regex to match CN/SAN

	numWorkers    = 2 // Number of concurrent matchers
	parallelFetch = 2 // Number of concurrent GetEntries fetches
	rootDomains   map[string]bool
)

func getLogUrls() ([]string, error) {
	var logList []string
	client := &http.Client{
		Timeout: time.Second * 5, // Set a 10-second timeout or adjust as needed
	}
	// Make an HTTP GET request
	resp, err := client.Get(logListUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the body of the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON into the struct
	var logsList LogsList
	if err := json.Unmarshal(body, &logsList); err != nil {
		return nil, err
	}

	// Loop through the operators and print their names
	for _, operator := range logsList.Operators {
		for _, ctlog := range operator.Logs {
			resp, err := client.Get(ctlog.URL + "ct/v1/get-sth")
			if err != nil {
				continue
			}
			if resp.StatusCode == http.StatusOK {
				logList = append(logList, ctlog.URL)
			}
			resp.Body.Close()
		}
	}
	return logList, nil
}

// Loads root domains from a file into the global rootDomains map
func loadRootDomains(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Initialize the map
	rootDomains = make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		rootDomains[scanner.Text()] = true
	}

	return scanner.Err()
}

// Checks if a domain is a subdomain of any root domain in the global map
func isSubdomain(domain string) bool {
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

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		if isSubdomain(parsedEntry.X509Cert.Subject.CommonName) {
			fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if isSubdomain(domain) {
				fmt.Println(domain)
			}
		}
	}
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		if isSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName) {
			fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if isSubdomain(domain) {
				fmt.Println(domain)
			}

		}
	}
}

func createRegexes(regexValue string) (*regexp.Regexp, *regexp.Regexp) {
	// Make a regex matcher
	var certRegex *regexp.Regexp
	precertRegex := regexp.MustCompile(regexValue)
	certRegex = precertRegex

	return certRegex, precertRegex
}

func createMatcherFromFlags() (interface{}, error) {
	certRegex, precertRegex := createRegexes(matchSubjectRegex)
	return scanner.MatchSubjectRegex{
		CertificateSubjectRegex:    certRegex,
		PrecertificateSubjectRegex: precertRegex}, nil
}

func scanLog(ctx context.Context, logURI string, wg *sync.WaitGroup, httpClient *http.Client) {
	defer wg.Done()

	var startIndex int64
	var endIndex int64
	var batchSize int

	log.Printf("Starting continuous scan for log: %s", logURI)
	logClient, err := client.New(logURI, httpClient, jsonclient.Options{UserAgent: "ct-go-scanlog/1.0"})
	if err != nil {
		log.Printf("Failed to create client for log %s: %v", logURI, err)
		return
	}

	sth, err := logClient.GetSTH(ctx)
	if err != nil {
		log.Printf("Failed to get STH for log %s: %v", logURI, err)
		return
	}
	if int64(sth.TreeSize) < int64(batchSize) {
		startIndex = 0
	} else {
		startIndex = int64(sth.TreeSize) - int64(batchSize)
	}
	endIndex = int64(sth.TreeSize)

	matcher, err := createMatcherFromFlags()
	if err != nil {
		log.Printf("Failed to create matcher for log %s: %v", logURI, err)
		return
	}
	time.Sleep(time.Second * 15)
	// Continous Scanning Loop
	for {
		opts := scanner.ScannerOptions{
			FetcherOptions: scanner.FetcherOptions{
				BatchSize:     int(endIndex) - int(startIndex),
				ParallelFetch: parallelFetch,
				StartIndex:    startIndex,
				// You might want to adjust EndIndex based on the STH or leave it 0 to scan up to the latest entry.
				EndIndex: endIndex,
			},
			Matcher:    matcher,
			NumWorkers: numWorkers,
		}
		// log.Printf("Log: %s == Index: %d", logURI, startIndex)
		s := scanner.NewScanner(logClient, opts)

		err = s.Scan(ctx, logCertInfo, logPrecertInfo)
		if err != nil {
			log.Printf("Failed to scan log %s: %v", logURI, err)
			// Consider whether to continue or break/return based on the type of error.
		}

		// Updating indices
		for {
			sth, err := logClient.GetSTH(ctx)
			if err != nil {
				log.Printf("Failed to get STH for log %s after scan: %v", logURI, err)
				// Decide on action based on error - break, continue, or retry getting STH.
			}

			if int64(sth.TreeSize) > endIndex+1 {
				startIndex = endIndex + 1
				endIndex = int64(sth.TreeSize)
				break
			}
			time.Sleep(time.Second * 30)
		}

		time.Sleep(time.Second * 30) // Wait for 30 seconds or adjust as needed=
	}
}

func main() {
	if len(os.Args) > 1 {
		loadRootDomains(os.Args[1])
	} else {
		fmt.Println("Please run with a roots.txt file...")
		fmt.Println("ex: ./gungnir roots.txt")
		os.Exit(1)
	}

	logURIs, err := getLogUrls()
	if err != nil {
		panic(err)
	}

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	for _, logURI := range logURIs {
		wg.Add(1)
		go scanLog(ctx, logURI, &wg, httpClient)
	}

	wg.Wait()
	log.Println("Done Scanning.")
}
