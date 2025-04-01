package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/anthdm/hollywood/actor"
	"github.com/g0ldencybersec/gungnir/pkg/utils"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/nats-io/nats.go"

	"github.com/fsnotify/fsnotify"
	"github.com/g0ldencybersec/gungnir/pkg/types"
)

// Global variables
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
	options     *Options
	logClients  []types.CtLog
	rootDomains map[string]bool
	// followFile     map[string]bool
	rateLimitMap   map[string]time.Duration
	entryTasksChan chan types.EntryTask
	watcher        *fsnotify.Watcher
	restartChan    chan struct{}
	outputMutex    sync.Mutex
	natsPub        bool
	natsConn       *nats.Conn
	actorPID       *actor.PID
	useActor       bool
	actorEngine    *actor.Engine
}

func (r *Runner) loadRootDomains() error {
	if r.options.RootList == "" {
		return nil
	}

	file, err := os.Open(r.options.RootList)
	if err != nil {
		return fmt.Errorf("failed to open root domains file: %v", err)
	}
	defer file.Close()

	r.rootDomains = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		r.rootDomains[scanner.Text()] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading root domains file: %v", err)
	}

	return nil
}

func (r *Runner) setupFileWatcher() error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}

	r.watcher = watcher

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op&fsnotify.Write == fsnotify.Write {
					if err := r.loadRootDomains(); err != nil {
						log.Printf("Error reloading domains: %v", err)
						continue
					}
					r.restartChan <- struct{}{}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("Watcher error: %v", err)
			}
		}
	}()

	return watcher.Add(r.options.RootList)
}

func NewRunner(options *Options) (*Runner, error) {
	runner := &Runner{
		options:     options,
		rootDomains: make(map[string]bool),
		restartChan: make(chan struct{}),
	}

	if err := runner.loadRootDomains(); err != nil {
		return nil, fmt.Errorf("failed to load root domains: %v", err)
	}

	// Verify that we have root domains if output directory is specified
	if runner.options.OutputDir != "" && len(runner.rootDomains) == 0 {
		return nil, fmt.Errorf("output directory specified but no root domains loaded")
	}

	if runner.options.WatchFile {
		if err := runner.setupFileWatcher(); err != nil {
			return nil, fmt.Errorf("failed to setup file watcher: %v", err)
		}
	}

	var err error
	runner.logClients, err = utils.PopulateLogs(logListUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to populate logs: %v", err)
	}

	// NATS setup if needed
	if runner.options.NatsSubject != "" && runner.options.NatsUrl != "" && runner.options.NatsCredFile != "" {
		nc, err := nats.Connect(runner.options.NatsUrl, nats.UserCredentials(runner.options.NatsCredFile))
		if err != nil {
			return nil, fmt.Errorf("failed to make nats connectoin: %v", err)
		}

		runner.natsConn = nc
		runner.natsPub = true
	} else {
		runner.natsConn = nil
		runner.natsPub = false
	}

	if runner.options.ActorPID != nil {
		runner.useActor = true
		runner.actorPID = runner.options.ActorPID

		if runner.options.ActorEngine != nil {
			runner.actorEngine = runner.options.ActorEngine
		} else {
			log.Println("No actor engine provided, creating a new one")
			// Fall back to creating a new engine if none is provided
			runner.actorEngine, err = actor.NewEngine(actor.EngineConfig{})
			if err != nil {
				return nil, fmt.Errorf("failed to create actor engine: %v", err)
			}
		}
	}

	runner.entryTasksChan = make(chan types.EntryTask, len(runner.logClients)*100)
	runner.rateLimitMap = defaultRateLimitMap

	return runner, nil
}
func (r *Runner) Run() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-signals:
				fmt.Fprintf(os.Stderr, "Shutdown signal received\n")
				cancel()
				return
			case <-r.restartChan:
				fmt.Fprintf(os.Stderr, "Restarting scan due to file update\n")
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				go r.startScan(ctx, &wg)
			}
		}
	}()

	r.startScan(ctx, &wg)

	wg.Wait()
	close(r.entryTasksChan)
	if r.watcher != nil {
		r.watcher.Close()
	}
	r.natsConn.Close()
	fmt.Fprintf(os.Stderr, "Gracefully shutdown all routines\n")
}

func (r *Runner) startScan(ctx context.Context, wg *sync.WaitGroup) {
	// Start entry workers
	for i := 0; i < len(r.logClients); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.entryWorker(ctx)
		}()
	}

	// Start scanning logs
	for _, ctl := range r.logClients {
		wg.Add(1)
		go r.scanLog(ctx, ctl, wg)
	}
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
				fmt.Fprintf(os.Stderr, "Retry %d: Failed to get initial STH for log %s: %v\n", retries+1, ctl.Client.BaseURI(), err)
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
						fmt.Fprintf(os.Stderr, "Failed to update STH: %v\n", err)
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
						fmt.Fprintf(os.Stderr, "%s is behind by: %d\n", ctl.Name, end-start)
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
							fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v", ctl.Name, err)
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
						fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v", ctl.Name, err)
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
				fmt.Fprintf(os.Stderr, "Failed to get parse entry %d: %v", index, err)
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
				fmt.Fprintln(os.Stderr, "Unknown entry")
			}
		}
	}
}

func (r *Runner) writeToHostFile(hostname string, data interface{}) error {
	// Early return if no output directory specified or if root domains is empty
	if r.options.OutputDir == "" || len(r.rootDomains) == 0 {
		return nil
	}

	// Find matching root domain
	var matchingRoot string
	for root := range r.rootDomains {
		if utils.IsSubdomain(hostname, map[string]bool{root: true}) {
			matchingRoot = root
			break
		}
	}

	// If no matching root domain found, return
	if matchingRoot == "" {
		return nil
	}

	// Create output directory if it doesn't exist
	if err := os.MkdirAll(r.options.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}

	// Sanitize root domain for filename
	safeRootDomain := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '.' || r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, matchingRoot)

	filePath := filepath.Join(r.options.OutputDir, safeRootDomain+".txt")

	// Use mutex to prevent concurrent file access
	r.outputMutex.Lock()
	defer r.outputMutex.Unlock()

	// Open file in append mode
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %v", err)
	}
	defer f.Close()

	var output string
	if r.options.JsonOutput {
		jsonData, err := json.Marshal(struct {
			Hostname string      `json:"hostname"`
			Data     interface{} `json:"data"`
		}{
			Hostname: hostname,
			Data:     data,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		output = string(jsonData) + "\n"
	} else {
		// output = fmt.Sprintf("Hostname: %s\nData: %v\n---\n", hostname, data)
		output = fmt.Sprintf("Hostname: %s\n", hostname)
	}

	if _, err := f.WriteString(output); err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	return nil
}

func (r *Runner) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	// Only process if we have root domains and output directory
	if r.options.OutputDir != "" && len(r.rootDomains) > 0 {
		// Handle CommonName
		if parsedEntry.X509Cert.Subject.CommonName != "" {
			if err := r.writeToHostFile(parsedEntry.X509Cert.Subject.CommonName, parsedEntry.X509Cert); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", parsedEntry.X509Cert.Subject.CommonName, err)
				}
			}
		}

		// Handle DNS names
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if err := r.writeToHostFile(domain, parsedEntry.X509Cert); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", domain, err)
				}
			}
		}
	} else if r.useActor {
		if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
			r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: parsedEntry.X509Cert.Subject.CommonName})
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: domain})
			}
		}
	} else if r.natsPub {
		if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
			err := r.natsConn.Publish(r.options.NatsSubject, []byte(parsedEntry.X509Cert.Subject.CommonName))
			if err != nil {
				log.Printf("Error writing to NATs: %v", err)
			}
		}
		for _, domain := range parsedEntry.X509Cert.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				err := r.natsConn.Publish(r.options.NatsSubject, []byte(domain))
				if err != nil {
					log.Printf("Error writing to NATs: %v", err)
				}
			}
		}
	} else {
		// Original stdout output behavior
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
			if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
				if r.options.JsonOutput {
					utils.JsonOutput(parsedEntry.X509Cert)
				} else {
					fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
				}
			}
			for _, domain := range parsedEntry.X509Cert.DNSNames {
				if utils.IsSubdomain(domain, r.rootDomains) {
					if r.options.JsonOutput {
						utils.JsonOutput(parsedEntry.X509Cert)
					} else {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}

func (r *Runner) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	// Only process if we have root domains and output directory
	if r.options.OutputDir != "" && len(r.rootDomains) > 0 {
		// Handle CommonName
		if parsedEntry.Precert.TBSCertificate.Subject.CommonName != "" {
			if err := r.writeToHostFile(parsedEntry.Precert.TBSCertificate.Subject.CommonName, parsedEntry.Precert.TBSCertificate); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", parsedEntry.Precert.TBSCertificate.Subject.CommonName, err)
				}
			}
		}

		// Handle DNS names
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if err := r.writeToHostFile(domain, parsedEntry.Precert.TBSCertificate); err != nil {
				if r.options.Verbose {
					log.Printf("Error writing to file for %s: %v", domain, err)
				}
			}
		}
	} else if r.useActor {
		if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
			r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: parsedEntry.Precert.TBSCertificate.Subject.CommonName})
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				r.actorEngine.Send(r.actorPID, &types.GungnirMessage{Domain: domain})
			}
		}
	} else if r.natsPub {
		if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
			err := r.natsConn.Publish(r.options.NatsSubject, []byte(parsedEntry.Precert.TBSCertificate.Subject.CommonName))
			if err != nil {
				log.Printf("Error writing to NATs: %v", err)
			}
		}
		for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
			if utils.IsSubdomain(domain, r.rootDomains) {
				err := r.natsConn.Publish(r.options.NatsSubject, []byte(domain))
				if err != nil {
					log.Printf("Error writing to NATs: %v", err)
				}
			}
		}
	} else {
		// Original stdout output behavior
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
			if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
				if r.options.JsonOutput {
					utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
				} else {
					fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
				}
			}
			for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
				if utils.IsSubdomain(domain, r.rootDomains) {
					if r.options.JsonOutput {
						utils.JsonOutput(parsedEntry.Precert.TBSCertificate)
					} else {
						fmt.Println(domain)
					}
				}
			}
		}
	}
}
