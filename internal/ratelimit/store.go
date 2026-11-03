package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Store holds rate limit counters and retry markers. Implementations must be
// safe for concurrent use.
type Store interface {
	// Increment atomically adds one to the counter at key, sets its expiry,
	// and returns the new value.
	Increment(ctx context.Context, key string, expiresAt time.Time) (int64, error)

	// Get returns the counters for keys. Missing keys are omitted.
	Get(ctx context.Context, keys []string) (map[string]int64, error)

	// PutIfAbsent creates a marker at key unless an unexpired one exists. It
	// returns false when the marker already exists.
	PutIfAbsent(ctx context.Context, key string, now, expiresAt time.Time) (bool, error)
}

// MemoryStore is an in-process Store for tests and local debugging. Its
// counters are not shared between lambda instances.
type MemoryStore struct {
	mu    sync.Mutex
	items map[string]memoryItem
}

type memoryItem struct {
	count     int64
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{items: map[string]memoryItem{}}
}

func (s *MemoryStore) Increment(ctx context.Context, key string, expiresAt time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item := s.items[key]
	item.count++
	item.expiresAt = expiresAt
	s.items[key] = item
	return item.count, nil
}

func (s *MemoryStore) Get(ctx context.Context, keys []string) (map[string]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(keys))
	for _, k := range keys {
		if item, ok := s.items[k]; ok {
			out[k] = item.count
		}
	}
	return out, nil
}

func (s *MemoryStore) PutIfAbsent(ctx context.Context, key string, now, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if item, ok := s.items[key]; ok && item.expiresAt.After(now) {
		return false, nil
	}
	s.items[key] = memoryItem{expiresAt: expiresAt}
	return true, nil
}

// Len returns the number of stored items.
func (s *MemoryStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Keys returns the stored keys.
func (s *MemoryStore) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.items))
	for k := range s.items {
		keys = append(keys, k)
	}
	return keys
}
