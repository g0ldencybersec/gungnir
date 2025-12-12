package deduplicator

import (
	"math"
	"sync"

	"github.com/bits-and-blooms/bloom/v3"
)

// FileDeduplicator provides per-file deduplication for file output mode.
// It maintains a separate Bloom filter for each output file, allowing
// independent deduplication per root domain file.
type FileDeduplicator struct {
	filters    map[string]*bloom.BloomFilter
	mu         sync.RWMutex
	enabled    bool
	capacity   uint
	falsePosRate float64
}

// NewFileDeduplicator creates a new file deduplicator with the given configuration.
func NewFileDeduplicator(config Config) *FileDeduplicator {
	return &FileDeduplicator{
		filters:      make(map[string]*bloom.BloomFilter),
		enabled:      config.Enabled,
		capacity:     config.Capacity,
		falsePosRate: config.FalsePosRate,
	}
}

// getOrCreateFilter gets the bloom filter for a file path, creating it if needed.
// Thread-safe.
func (fd *FileDeduplicator) getOrCreateFilter(filePath string) *bloom.BloomFilter {
	if !fd.enabled {
		return nil
	}

	fd.mu.RLock()
	filter, exists := fd.filters[filePath]
	fd.mu.RUnlock()

	if exists {
		return filter
	}

	// Create new filter for this file
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// Double-check after acquiring write lock
	if filter, exists := fd.filters[filePath]; exists {
		return filter
	}

	filter = bloom.NewWithEstimates(fd.capacity, fd.falsePosRate)
	fd.filters[filePath] = filter
	return filter
}

// IsDuplicate checks if a domain has been seen for a specific file.
// Returns true if the domain is a duplicate for this file, false if it's new.
// Thread-safe.
func (fd *FileDeduplicator) IsDuplicate(filePath, domain string) bool {
	if !fd.enabled {
		return false
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return false
	}

	filter := fd.getOrCreateFilter(filePath)
	if filter == nil {
		return false
	}

	fd.mu.RLock()
	defer fd.mu.RUnlock()

	return filter.TestString(normalized)
}

// Add marks a domain as seen for a specific file.
// Thread-safe.
func (fd *FileDeduplicator) Add(filePath, domain string) {
	if !fd.enabled {
		return
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return
	}

	filter := fd.getOrCreateFilter(filePath)
	if filter == nil {
		return
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	filter.AddString(normalized)
}

// CheckAndAdd checks if a domain is duplicate for a file and adds it if not.
// Returns true if the domain was already seen (duplicate), false if it's new.
// This is more efficient than calling IsDuplicate followed by Add.
// Thread-safe.
func (fd *FileDeduplicator) CheckAndAdd(filePath, domain string) bool {
	if !fd.enabled {
		return false
	}

	normalized := normalizeDomain(domain)
	if normalized == "" {
		return false
	}

	filter := fd.getOrCreateFilter(filePath)
	if filter == nil {
		return false
	}

	fd.mu.Lock()
	defer fd.mu.Unlock()

	// Check if already seen
	if filter.TestString(normalized) {
		return true // Duplicate
	}

	// Add to filter
	filter.AddString(normalized)
	return false // New domain
}

// GetMemoryUsage returns an estimate of total memory usage in bytes.
func (fd *FileDeduplicator) GetMemoryUsage() uint64 {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	if !fd.enabled {
		return 0
	}

	// Calculate memory per filter
	bitsPerFilter := float64(fd.capacity) * -math.Log(fd.falsePosRate) / (math.Log(2) * math.Log(2))
	bytesPerFilter := uint64(math.Ceil(bitsPerFilter / 8))

	// Multiply by number of filters
	return bytesPerFilter * uint64(len(fd.filters))
}

// GetStats returns statistics about the file deduplicator.
func (fd *FileDeduplicator) GetStats() FileStats {
	fd.mu.RLock()
	defer fd.mu.RUnlock()

	stats := FileStats{
		Enabled:      fd.enabled,
		Capacity:     fd.capacity,
		FalsePosRate: fd.falsePosRate,
		FileCount:    uint(len(fd.filters)),
		MemoryUsage:  fd.GetMemoryUsage(),
	}

	return stats
}

// FileStats holds statistics about the file deduplicator.
type FileStats struct {
	Enabled      bool
	Capacity     uint
	FalsePosRate float64
	FileCount    uint
	MemoryUsage  uint64
}

