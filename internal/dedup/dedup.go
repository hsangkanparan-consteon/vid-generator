package dedup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	"consteon.com/qr-generator/internal/crypto"
	"github.com/cespare/xxhash/v2"
	"github.com/redis/go-redis/v9"
)

var (
	ErrDuplicateID = errors.New("ID already exists and cannot be duplicated")
)

const (
	// DefaultBloomBits = 95,850,584 bits (~11.98 MB for 10M items @ 1% FPR)
	DefaultBloomBits uint64 = 95850584
	DefaultNumHashes uint32 = 7
)

// Engine handles uniqueness verification and Bloom filtering for Location and Asset IDs.
type Engine struct {
	rdb       *redis.Client
	useRedis  bool
	bloomBits uint64
	numHashes uint32

	// In-memory fallback for local dev/testing
	mu         sync.RWMutex
	memBitsets map[string][]byte
	memSets    map[string]map[string]struct{}
}

// NewEngine creates a new Deduplication and Bloom filter engine.
func NewEngine(rdb *redis.Client) *Engine {
	e := &Engine{
		rdb:        rdb,
		useRedis:   rdb != nil,
		bloomBits:  DefaultBloomBits,
		numHashes:  DefaultNumHashes,
		memBitsets: make(map[string][]byte),
		memSets:    make(map[string]map[string]struct{}),
	}
	return e
}

// NewEngineFromEnv initializes the Engine from environment variables.
func NewEngineFromEnv(ctx context.Context) *Engine {
	host := os.Getenv("REDIS_HOST")
	port := os.Getenv("REDIS_PORT")
	if port == "" {
		port = "6379"
	}
	password := os.Getenv("REDIS_PASSWORD")

	if host == "" {
		// Fallback to in-memory engine
		return NewEngine(nil)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:         fmt.Sprintf("%s:%s", host, port),
		Password:     password,
		DB:           0,
		DialTimeout:  2 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		PoolSize:     20,
	})

	// Test connection
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := rdb.Ping(pingCtx).Err(); err != nil {
		fmt.Printf("[dedup] Warning: Redis at %s:%s unreachable (%v), falling back to in-memory dedup\n", host, port, err)
		return NewEngine(nil)
	}

	fmt.Printf("[dedup] Connected to Redis at %s:%s for Bloom deduplication\n", host, port)
	return NewEngine(rdb)
}

// GenerateUniqueLocationID generates a fresh 16-byte random Location ID and guarantees 0 redundancy.
func (e *Engine) GenerateUniqueLocationID(ctx context.Context, tenantID string) (raw16 [16]byte, unencryptedID string, err error) {
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := rand.Read(raw16[:]); err != nil {
			return [16]byte{}, "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		unencryptedID = "0" + crypto.EncodeBase64URL(raw16[:])

		isDup, err := e.RegisterLocationID(ctx, tenantID, unencryptedID)
		if err != nil {
			return [16]byte{}, "", err
		}
		if !isDup {
			return raw16, unencryptedID, nil
		}
		// In the astronomically unlikely event of a collision, retry loop
	}
	return [16]byte{}, "", fmt.Errorf("failed to generate unique location ID after 10 attempts")
}

// GenerateUniqueAssetID generates a fresh 16-byte random Asset ID and guarantees 0 redundancy.
func (e *Engine) GenerateUniqueAssetID(ctx context.Context, tenantID string) (raw16 [16]byte, unencryptedID string, err error) {
	for attempt := 0; attempt < 10; attempt++ {
		if _, err := rand.Read(raw16[:]); err != nil {
			return [16]byte{}, "", fmt.Errorf("failed to generate random bytes: %w", err)
		}
		unencryptedID = "0" + crypto.EncodeBase64URL(raw16[:])

		isDup, err := e.RegisterAssetID(ctx, tenantID, unencryptedID)
		if err != nil {
			return [16]byte{}, "", err
		}
		if !isDup {
			return raw16, unencryptedID, nil
		}
	}
	return [16]byte{}, "", fmt.Errorf("failed to generate unique asset ID after 10 attempts")
}

// RegisterLocationID registers a Location ID and returns true if it was already registered (duplicate).
func (e *Engine) RegisterLocationID(ctx context.Context, tenantID, locationID string) (isDuplicate bool, err error) {
	bloomKey := fmt.Sprintf("bloom:%s:locations", tenantID)
	setKey := fmt.Sprintf("set:%s:locations", tenantID)
	return e.checkAndRegister(ctx, bloomKey, setKey, locationID)
}

// RegisterAssetID registers an Asset ID and returns true if it was already registered (duplicate).
func (e *Engine) RegisterAssetID(ctx context.Context, tenantID, assetID string) (isDuplicate bool, err error) {
	bloomKey := fmt.Sprintf("bloom:%s:assets", tenantID)
	setKey := fmt.Sprintf("set:%s:assets", tenantID)
	return e.checkAndRegister(ctx, bloomKey, setKey, assetID)
}

// IsLocationIDRegistered checks if a Location ID is registered.
func (e *Engine) IsLocationIDRegistered(ctx context.Context, tenantID, locationID string) (bool, error) {
	bloomKey := fmt.Sprintf("bloom:%s:locations", tenantID)
	setKey := fmt.Sprintf("set:%s:locations", tenantID)
	return e.isRegistered(ctx, bloomKey, setKey, locationID)
}

// IsAssetIDRegistered checks if an Asset ID is registered.
func (e *Engine) IsAssetIDRegistered(ctx context.Context, tenantID, assetID string) (bool, error) {
	bloomKey := fmt.Sprintf("bloom:%s:assets", tenantID)
	setKey := fmt.Sprintf("set:%s:assets", tenantID)
	return e.isRegistered(ctx, bloomKey, setKey, assetID)
}

// checkAndRegister performs atomic Bloom & Set registration.
func (e *Engine) checkAndRegister(ctx context.Context, bloomKey, setKey, item string) (isDuplicate bool, err error) {
	if e.useRedis {
		// 1. Check exact Set membership atomically using SADD
		added, err := e.rdb.SAdd(ctx, setKey, item).Result()
		if err != nil {
			return false, fmt.Errorf("redis sadd failed: %w", err)
		}
		if added == 0 {
			// Item already existed in Set -> Duplicate
			return true, nil
		}

		// 2. Item is new -> Update Bloom Filter bitset
		offsets := e.getOffsets(item)
		pipe := e.rdb.Pipeline()
		for _, offset := range offsets {
			pipe.SetBit(ctx, bloomKey, int64(offset), 1)
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return false, fmt.Errorf("redis setbit pipeline failed: %w", err)
		}
		return false, nil
	}

	// In-memory fallback
	e.mu.Lock()
	defer e.mu.Unlock()

	set, exists := e.memSets[setKey]
	if !exists {
		set = make(map[string]struct{})
		e.memSets[setKey] = set
	}
	if _, found := set[item]; found {
		return true, nil
	}
	set[item] = struct{}{}

	// Update in-memory bloom bitset
	offsets := e.getOffsets(item)
	bitset, exists := e.memBitsets[bloomKey]
	byteSize := (e.bloomBits + 7) / 8
	if !exists || uint64(len(bitset)) < byteSize {
		bitset = make([]byte, byteSize)
		e.memBitsets[bloomKey] = bitset
	}
	for _, offset := range offsets {
		byteIdx := offset / 8
		bitIdx := offset % 8
		bitset[byteIdx] |= (1 << bitIdx)
	}

	return false, nil
}

// isRegistered checks if an item exists via Bloom Filter then Set.
func (e *Engine) isRegistered(ctx context.Context, bloomKey, setKey, item string) (bool, error) {
	if e.useRedis {
		// 1. Fast Bloom check
		offsets := e.getOffsets(item)
		pipe := e.rdb.Pipeline()
		cmds := make([]*redis.IntCmd, len(offsets))
		for i, offset := range offsets {
			cmds[i] = pipe.GetBit(ctx, bloomKey, int64(offset))
		}
		if _, err := pipe.Exec(ctx); err != nil {
			return false, err
		}

		// If any bit is 0, item is 100% guaranteed NOT in set
		for _, cmd := range cmds {
			if cmd.Val() == 0 {
				return false, nil
			}
		}

		// 2. All bloom bits were 1 -> Confirm with exact Set lookup (handles FPR)
		isMember, err := e.rdb.SIsMember(ctx, setKey, item).Result()
		if err != nil {
			return false, err
		}
		return isMember, nil
	}

	// In-memory fallback
	e.mu.RLock()
	defer e.mu.RUnlock()

	set, exists := e.memSets[setKey]
	if !exists {
		return false, nil
	}
	_, found := set[item]
	return found, nil
}

// getOffsets computes k bit positions using double hashing (Kirsch-Mitzenmacher).
// g_i(x) = (h1(x) + i * h2(x)) mod m
func (e *Engine) getOffsets(item string) []uint64 {
	data := []byte(item)
	h1 := xxhash.Sum64(data)

	// h2 via FNV-1a 64-bit
	f := fnv.New64a()
	f.Write(data)
	h2 := f.Sum64()
	if h2 == 0 {
		h2 = 1
	}

	offsets := make([]uint64, e.numHashes)
	for i := uint32(0); i < e.numHashes; i++ {
		combined := h1 + uint64(i)*h2
		offsets[i] = combined % e.bloomBits
	}
	return offsets
}

// Hash128 computes a 16-byte deterministic hash for a string.
func Hash128(input string) [16]byte {
	h := sha256.Sum256([]byte(input))
	var out [16]byte
	copy(out[:], h[:16])
	return out
}

// IntToUID converts uint64 to 5-byte big endian.
func IntToUID(val uint64) [5]byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], val)
	var out [5]byte
	copy(out[:], buf[3:])
	return out
}
