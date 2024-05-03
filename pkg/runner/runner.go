package runner

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/g0ldencybersec/gungnir/pkg/types"
	"github.com/g0ldencybersec/gungnir/pkg/utils"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

var (
	logListUrl          = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	defaultRateLimitMap = map[string]time.Duration{
		"Google":        time.Millisecond * 1,
		"Sectigo":       time.Second * 4,
		"Let's Encrypt": time.Second * 1,
		"DigiCert":      time.Second * 1,
		"TrustAsia":     time.Second * 1,
	}
)

type Runner struct {
	options        *Options
	logClients     []types.CtLog
	rootDomains    map[string]bool
	rateLimitMap   map[string]time.Duration
	entryTasksChan chan types.EntryTask
}

func NewRunner(options *Options) (*Runner, error) {
	var err error
	// Parse Options
	runner := &Runner{options: options}

	// Load root domains if any
	runner.rootDomains = map[string]bool{}
	if runner.options.RootList != "" {
		file, err := os.Open(runner.options.RootList)
		if err != nil {
			panic(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			runner.rootDomains[scanner.Text()] = true
		}

	}

	// Collect CT Logs
	runner.logClients, err = utils.PopulateLogs(logListUrl)
	if err != nil {
		panic(err)
	}

	runner.entryTasksChan = make(chan types.EntryTask, len(runner.logClients)*100)

	// Copy rate limit map
	runner.rateLimitMap = defaultRateLimitMap

	return runner, nil
}

func (r *Runner) Run() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		fmt.Println("Shutdown signal received")
		cancel() // Cancel the context
	}()

	// Parsing results workers
	for i := 0; i < len(r.logClients); i++ {
		wg.Add(1) // Don't forget to add to the WaitGroup for each worker
		go func() {
			defer wg.Done()
			r.entryWorker(ctx)
		}()
	}

	// Start scanning logs
	for _, ctl := range r.logClients {
		wg.Add(1)
		go r.scanLog(ctx, ctl, &wg)
	}

	wg.Wait()               // Wait for all goroutines to finish
	close(r.entryTasksChan) // Close the channel after all tasks are complete
	fmt.Println("Gracefully shutdown all routines")
}

func (r *Runner) entryWorker(ctx context.Context) {
	for {
		select {
		case task, ok := <-r.entryTasksChan:
			if !ok {
				return // Channel closed, terminate the goroutine
			}
			r.processEntries(task.Entries, task.Index)
		case <-ctx.Done():
			return // Context cancelled, terminate the goroutine
		}
	}
}

func (r *Runner) scanLog(ctx context.Context, ctl types.CtLog, wg *sync.WaitGroup) {
	defer wg.Done()

	tickerDuration := time.Second // Default duration
	for key := range r.rateLimitMap {
		if strings.Contains(ctl.Name, key) {
			tickerDuration = r.rateLimitMap[key]
			break
		}
	}

	// Is this a google log?
	IsGoogleLog := strings.Contains(ctl.Name, "Google")

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	var start, end int64
	var err error

	// Retry fetching the initial STH with context-aware back-off
	for retries := 0; retries < 3; retries++ {
		if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
			if r.options.Verbose {
				log.Printf("Retry %d: Failed to get initial STH for log %s: %v", retries+1, ctl.Client.BaseURI(), err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second): // Wait with context awareness
				continue
			}
		}
		break
	}

	start = end - 20

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if start >= end {
				if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
					if r.options.Verbose {
						log.Printf("Failed to update STH: %v", err)
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(60 * time.Second): // Wait with context awareness
					}
					continue
				}
				if r.options.Debug {
					if end-start > 25 {
						fmt.Printf("%s is behind by: %d\n", ctl.Name, end-start)
					}
				}
				continue
			}

			// Work with google logs
			if IsGoogleLog {
				for start < end {
					batchEnd := start + 32
					if batchEnd > end {
						batchEnd = end
					}
					entries, err := ctl.Client.GetRawEntries(ctx, start, batchEnd)
					if err != nil {
						if r.options.Verbose {
							log.Printf("Error fetching entries for %s: %v", ctl.Name, err)
						}
						select {
						case <-ctx.Done():
							return
						case <-time.After(30 * time.Second): // Wait with context awareness
						}
						break // Break this loop on error, wait for the next ticker tick.
					}

					if len(entries.Entries) > 0 {
						r.entryTasksChan <- types.EntryTask{
							Entries: entries,
							Index:   start,
						}
						start += int64(len(entries.Entries))
					} else {
						break // No more entries to process, break the loop.
					}
				}
				continue // Continue with the outer loop.
			} else { // Non Google handler
				entries, err := ctl.Client.GetRawEntries(ctx, start, end)
				if err != nil {
					if r.options.Verbose {
						log.Printf("Error fetching entries for %s: %v", ctl.Name, err)
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(60 * time.Second): // Wait with context awareness
					}
					continue
				}

				if len(entries.Entries) > 0 {
					r.entryTasksChan <- types.EntryTask{
						Entries: entries,
						Index:   start,
					}
					start += int64(len(entries.Entries))
				}
			}
		}
	}
}

func (r *Runner) fetchAndUpdateSTH(ctx context.Context, ctl types.CtLog, end *int64) error {
	wsth, err := ctl.Client.GetSTH(ctx)
	if err != nil {
		return err
	}
	*end = int64(wsth.TreeSize)
	return nil
}

func (r *Runner) processEntries(results *ct.GetEntriesResponse, start int64) {
	index := start

	for _, entry := range results.Entries {
		index++
		rle, err := ct.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			if r.options.Verbose {
				log.Printf("Failed to get parse entry %d: %v", index, err)
			}
			break
		}

		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			r.logCertInfo(rle)
		case ct.PrecertLogEntryType:
			r.logPrecertInfo(rle)
		default:
			if r.options.Verbose {
				log.Println("Unknown entry")
			}
		}
	}
}

func (r *Runner) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		if len(r.rootDomains) == 0 {
			if r.options.JsonOutput {
				utils.JsonOutput(parsedEntry.X509Cert)
			} else {
				fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
				for _, domain := range parsedEntry.X509Cert.DNSNames {
					fmt.Println(domain)
				}
			}
		} else {
			if r.options.JsonOutput {
				if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
					utils.JsonOutput(parsedEntry.X509Cert)
					return
				}
				for _, domain := range parsedEntry.X509Cert.DNSNames {
					if utils.IsSubdomain(domain, r.rootDomains) {
						utils.JsonOutput(parsedEntry.X509Cert)
						break
					}
				}
			} else {
				if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
					fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
				}
				for _, domain := range parsedEntry.X509Cert.DNSNames {
					if utils.IsSubdomain(domain, r.rootDomains) {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func (r *Runner) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		if len(r.rootDomains) == 0 {
			if r.options.JsonOutput {
				utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
			} else {
				fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
					fmt.Println(domain)
				}
			}
		} else {
			if r.options.JsonOutput {
				if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
					utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
					return
				}
				for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
					if utils.IsSubdomain(domain, r.rootDomains) {
						utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
						break
					}
				}
			} else {
				if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
					fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				}
				for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
					if utils.IsSubdomain(domain, r.rootDomains) {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}
