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

	rootDomains map[string]bool
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

	matcher, err := createMatcherFromFlags()
	if err != nil {
		log.Printf("Failed to create matcher for log %s: %v", logURI, err)
		return
	}
	time.Sleep(time.Second * 10)
	// Continous Scanning Loop

	certScanner := scanner.NewScanner(logClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     100,
			ParallelFetch: 1,
			StartIndex:    int64(sth.TreeSize), // Start at the latest STH to skip all the past certificates
			Continuous:    true,
		},
		Matcher:     matcher,
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  1000,
	})

	err = certScanner.Scan(ctx, logCertInfo, logPrecertInfo)
	if err != nil {
		log.Printf("Failed to scan log %s: %v", logURI, err)
		// Consider whether to continue or break/return based on the type of error.
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
		Timeout: 30 * time.Second,
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
