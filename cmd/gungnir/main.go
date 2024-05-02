package main

import (
	"github.com/g0ldencybersec/gungnir/pkg/runner"
)

// var (
// 	logListUrl  = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
// 	rootDomains map[string]bool
// 	rootList    string
// 	verbose     bool
// 	debug       bool
// )

// var getByScheme = map[string]func(*url.URL) ([]byte, error){
// 	"http":  readHTTP,
// 	"https": readHTTP,
// 	"file": func(u *url.URL) ([]byte, error) {
// 		return os.ReadFile(u.Path)
// 	},
// }

// // readHTTP fetches and reads data from an HTTP-based URL.
// func readHTTP(u *url.URL) ([]byte, error) {
// 	resp, err := http.Get(u.String())
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	return io.ReadAll(resp.Body)
// }

// // readURL fetches and reads data from an HTTP-based or filesystem URL.
// func readURL(u *url.URL) ([]byte, error) {
// 	s := u.Scheme
// 	queryFn, ok := getByScheme[s]
// 	if !ok {
// 		return nil, fmt.Errorf("failed to identify suitable scheme for the URL %q", u.String())
// 	}
// 	return queryFn(u)
// }

// func populateLogs(logListURL string) ([]ctLog, error) {
// 	u, err := url.Parse(logListURL)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse URL: %v", err)
// 	}
// 	body, err := readURL(u)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to get log list data: %v", err)
// 	}
// 	// Get data for all usable logs.
// 	logList, err := loglist3.NewFromJSON(body)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to parse JSON: %v", err)
// 	}
// 	usable := logList.SelectByStatus([]loglist3.LogStatus{loglist3.UsableLogStatus, loglist3.PendingLogStatus, loglist3.ReadOnlyLogStatus, loglist3.QualifiedLogStatus, loglist3.RetiredLogStatus})
// 	var logs []ctLog
// 	for _, operator := range usable.Operators {
// 		for _, log := range operator.Logs {
// 			logID := base64.StdEncoding.EncodeToString(log.LogID)
// 			c, err := createLogClient(log.Key, log.URL)
// 			if err != nil {
// 				return nil, fmt.Errorf("failed to create log client: %v", err)
// 			}
// 			l := ctLog{
// 				id:     logID,
// 				name:   log.Description,
// 				client: c,
// 			}
// 			logs = append(logs, l)
// 		}
// 	}
// 	return logs, nil
// }

// // createLogClient creates a CT log client from a public key and URL.
// func createLogClient(key []byte, url string) (*client.LogClient, error) {
// 	pemPK := pem.EncodeToMemory(&pem.Block{
// 		Type:  "PUBLIC KEY",
// 		Bytes: key,
// 	})
// 	opts := jsonclient.Options{PublicKey: string(pemPK), UserAgent: "gungnir-" + uuid.New().String()}
// 	c, err := client.New(url, &http.Client{
// 		Timeout: 27 * time.Second,
// 		Transport: &http.Transport{
// 			TLSHandshakeTimeout:   30 * time.Second,
// 			ResponseHeaderTimeout: 30 * time.Second,
// 			MaxIdleConnsPerHost:   10,
// 			DisableKeepAlives:     false,
// 			MaxIdleConns:          100,
// 			IdleConnTimeout:       90 * time.Second,
// 			ExpectContinueTimeout: 1 * time.Second,
// 		},
// 	}, opts)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create JSON client: %v", err)
// 	}
// 	return c, nil
// }

// // Loads root domains from a file into the global rootDomains map
// func loadRootDomains(filePath string) error {
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		return err
// 	}
// 	defer file.Close()

// 	// Initialize the map
// 	rootDomains = make(map[string]bool)

// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		rootDomains[scanner.Text()] = true
// 	}

// 	return scanner.Err()
// }

// // Checks if a domain is a subdomain of any root domain in the global map
// func isSubdomain(domain string) bool {
// 	if _, ok := rootDomains[domain]; ok {
// 		return true
// 	}

// 	parts := strings.Split(domain, ".")
// 	for i := range parts {
// 		parentDomain := strings.Join(parts[i:], ".")
// 		if _, ok := rootDomains[parentDomain]; ok {
// 			return true
// 		}
// 	}

// 	return false
// }

// // Prints out a short bit of info about |cert|, found at |index| in the
// // specified log
// func logCertInfo(entry *ct.RawLogEntry) {
// 	parsedEntry, err := entry.ToLogEntry()
// 	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
// 		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
// 	} else {
// 		if len(rootDomains) == 0 {
// 			fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
// 			for _, domain := range parsedEntry.X509Cert.DNSNames {
// 				fmt.Println(domain)
// 			}
// 		} else {
// 			if isSubdomain(parsedEntry.X509Cert.Subject.CommonName) {
// 				fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
// 			}
// 			for _, domain := range parsedEntry.X509Cert.DNSNames {
// 				if isSubdomain(domain) {
// 					fmt.Println(domain)
// 				}
// 			}
// 		}
// 	}
// }

// // Prints out a short bit of info about |precert|, found at |index| in the
// // specified log
// func logPrecertInfo(entry *ct.RawLogEntry) {
// 	parsedEntry, err := entry.ToLogEntry()
// 	if x509.IsFatal(err) || parsedEntry.Precert == nil {
// 		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
// 	} else {
// 		if len(rootDomains) == 0 {
// 			fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
// 			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
// 				fmt.Println(domain)
// 			}
// 		} else {
// 			if isSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName) {
// 				fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
// 			}
// 			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
// 				if isSubdomain(domain) {
// 					fmt.Println(domain)
// 				}
// 			}
// 		}
// 	}
// }

// func scanLog(ctx context.Context, ctl ctLog, wg *sync.WaitGroup) {
// 	defer wg.Done()

// 	var err error
// 	var start int64
// 	var end int64
// 	var ticker *time.Ticker
// 	baseErrTime := 60
// 	errorCount := 1

// 	errTicker := time.NewTicker(time.Second * time.Duration(baseErrTime))
// 	if strings.Contains(ctl.name, "Google") {
// 		ticker = time.NewTicker(time.Millisecond * 1)
// 	} else if strings.Contains(ctl.name, "Sectigo") {
// 		ticker = time.NewTicker(time.Second * 4)
// 	} else {
// 		ticker = time.NewTicker(time.Second * 1)
// 	}

// 	for {
// 		ctl.wsth, err = ctl.client.GetSTH(ctx)
// 		if err != nil {
// 			if verbose {
// 				log.Printf("Failed to get initial STH for log %s: %v", ctl.client.BaseURI(), err)
// 			}
// 			<-errTicker.C
// 			errorCount++ // Increment Error count
// 			errTicker.Reset(time.Second * (time.Duration(baseErrTime) * time.Duration(errorCount)))
// 		} else {
// 			errorCount = 1 // Reset to 1
// 			errTicker.Reset(time.Second * time.Duration(baseErrTime))
// 			break
// 		}
// 	}

// 	start = int64(ctl.wsth.TreeSize) - 100
// 	end = int64(ctl.wsth.TreeSize)

// 	for {
// 		<-ticker.C // Wait for the next tick.

// 		entries, err := ctl.client.GetRawEntries(ctx, start, end)
// 		if err != nil {
// 			if verbose {
// 				log.Printf("Failed to get ENTRIES for log %s: %v\n start: %d  end : %d", ctl.client.BaseURI(), err, start, end)
// 			}
// 			<-errTicker.C // Wait for the next tick.
// 			errorCount++
// 			errTicker.Reset(time.Second * (time.Duration(baseErrTime) * time.Duration(errorCount)))
// 			continue
// 		} else {
// 			errorCount = 1
// 			errTicker.Reset(time.Second * time.Duration(baseErrTime))
// 		}

// 		start = processEntries(entries, start)

// 		if debug {
// 			if end-start > 1 {
// 				fmt.Printf("%s end was: %d but made it to %d --> difference of: %d\n", ctl.name, end, start, end-start)
// 			}
// 		}

// 		// Get next end
// 		for {
// 			<-ticker.C // Wait for the next tick.
// 			ctl.wsth, err = ctl.client.GetSTH(ctx)
// 			if err != nil {
// 				if verbose {
// 					log.Printf("Failed to get continual STH for log %s: %v", ctl.client.BaseURI(), err)
// 				}
// 				<-errTicker.C // Wait for the next tick.
// 				errorCount++
// 				errTicker.Reset(time.Second * (time.Duration(baseErrTime) * time.Duration(errorCount)))
// 			} else {
// 				errorCount = 1
// 				errTicker.Reset(time.Second * time.Duration(baseErrTime))
// 				end = int64(ctl.wsth.TreeSize)
// 				// Check for overlap
// 				if start >= end {
// 					<-errTicker.C // Wait for the next tick.
// 					errorCount++
// 					errTicker.Reset(time.Second * (time.Duration(baseErrTime) * time.Duration(errorCount)))
// 					continue
// 				} else {
// 					errorCount = 1
// 					errTicker.Reset(time.Second * time.Duration(baseErrTime))
// 					break
// 				}
// 			}
// 		}
// 	}
// }

// func processEntries(results *ct.GetEntriesResponse, start int64) int64 {
// 	index := start

// 	for _, entry := range results.Entries {
// 		index++
// 		rle, err := ct.RawLogEntryFromLeaf(index, &entry)
// 		if err != nil {
// 			if verbose {
// 				log.Printf("Failed to get parse entry %d: %v", index, err)
// 			}
// 			break
// 		}

// 		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
// 		case ct.X509LogEntryType:
// 			logCertInfo(rle)
// 		case ct.PrecertLogEntryType:
// 			logPrecertInfo(rle)
// 		default:
// 			if verbose {
// 				log.Println("Unknown entry")
// 			}
// 		}
// 	}
// 	return index
// }

func main() {
	options := runner.ParseOptions()
	runner, err := runner.NewRunner(options)
	if err != nil {
		panic(err)
	}

	runner.Run()
}
