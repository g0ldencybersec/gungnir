package deduplicator

import (
	"math"
	"strings"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
)

// Deduplicator provides memory-efficient domain deduplication using a Bloom filter.
// It uses constant memory regardless of the number of domains processed.
type Deduplicator struct {
	filter     *bloom.BloomFilter
	mu         sync.RWMutex
	enabled    bool
	capacity   uint
	falsePosRate float64
}

// Config holds configuration for the deduplicator.
type Config struct {
	Enabled      bool
	Capacity     uint
	FalsePosRate float64
}

// NewDeduplicator creates a new deduplicator with the given configuration.
// If enabled is false, all checks will return false (no duplicates).
func NewDeduplicator(config Config) *Deduplicator {
	d := &Deduplicator{
		enabled:      config.Enabled,
		capacity:     config.Capacity,
		falsePosRate: config.FalsePosRate,
	}

	if config.Enabled {
		// Calculate optimal number of hash functions and bits
		// Formula: m = -n * ln(p) / (ln(2)^2) where n=capacity, p=falsePosRate
		bits := uint(float64(config.Capacity) * -math.Log(config.FalsePosRate) / (math.Log(2) * math.Log(2)))
		d.filter = bloom.NewWithEstimates(config.Capacity, config.FalsePosRate)
		_ = bits // bits is calculated automatically by NewWithEstimates
	}

	return d
}

// normalizeDomain normalizes a domain name for consistent deduplication.
// Converts to lowercase and trims whitespace.
func normalizeDomain(domain string) string {
	return strings.ToLower(strings.TrimSpace(domain))
}

// IsDuplicate checks if a domain has been seen before.
// Returns true if the domain is a duplicate, false if it's new.
// Thread-safe.
func (d *Deduplicator) IsDuplicate(domain string) bool {
	if !d.enabled {
		return false
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.filter == nil {
		return false
	}

	// Bloom filter: if Test returns true, domain might be duplicate
	// If Test returns false, domain is definitely new
	return d.filter.TestString(normalized)
}

// Add marks a domain as seen.
// Thread-safe.
func (d *Deduplicator) Add(domain string) {
	if !d.enabled {
		return
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.filter != nil {
		d.filter.AddString(normalized)
	}
}

// CheckAndAdd checks if a domain is duplicate and adds it if not.
// Returns true if the domain was already seen (duplicate), false if it's new.
// This is more efficient than calling IsDuplicate followed by Add.
// Thread-safe.
func (d *Deduplicator) CheckAndAdd(domain string) bool {
	if !d.enabled {
		return false
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.filter == nil {
		return false
	}

	// Check if already seen
	if d.filter.TestString(normalized) {
		return true // Duplicate
	}

	// Add to filter
	d.filter.AddString(normalized)
	return false // New domain
}

// GetMemoryUsage returns an estimate of memory usage in bytes.
func (d *Deduplicator) GetMemoryUsage() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.filter == nil {
		return 0
	}

	// Bloom filter memory = m bits where m = -n * ln(p) / (ln(2)^2)
	bits := float64(d.capacity) * -math.Log(d.falsePosRate) / (math.Log(2) * math.Log(2))
	return uint64(math.Ceil(bits / 8)) // Convert bits to bytes
}

// GetStats returns statistics about the deduplicator.
func (d *Deduplicator) GetStats() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := Stats{
		Enabled:      d.enabled,
		Capacity:     d.capacity,
		FalsePosRate: d.falsePosRate,
		MemoryUsage:  d.GetMemoryUsage(),
	}

	if d.filter != nil {
		// Bloom filters don't track exact count, so we estimate based on capacity
		// This is a rough approximation - actual count could be anywhere from 0 to capacity
		// For more accurate tracking, you'd need to maintain a separate counter
		stats.ApproximateCount = 0 // Set to 0 as we can't accurately determine without tracking
	}

	return stats
}

// Stats holds statistics about the deduplicator.
type Stats struct {
	Enabled         bool
	Capacity        uint
	FalsePosRate    float64
	MemoryUsage     uint64
	ApproximateCount uint
}

