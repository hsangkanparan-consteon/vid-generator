package dedup

import (
	"context"
	"testing"
)

func TestDeduplicationAndBloom(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(nil) // In-memory mode

	tenantID := "62000000000000"

	// 1. Test GenerateUniqueLocationID
	raw1, id1, err := engine.GenerateUniqueLocationID(ctx, tenantID)
	if err != nil {
		t.Fatalf("failed to generate location ID: %v", err)
	}
	if len(raw1) != 16 || len(id1) != 23 {
		t.Fatalf("invalid generated location ID format: %s", id1)
	}

	// 2. Check that generated ID is now registered
	isReg, err := engine.IsLocationIDRegistered(ctx, tenantID, id1)
	if err != nil || !isReg {
		t.Fatalf("expected ID %s to be registered, got %v (err: %v)", id1, isReg, err)
	}

	// 3. Attempting to register the exact same ID again should flag it as duplicate
	isDup, err := engine.RegisterLocationID(ctx, tenantID, id1)
	if err != nil {
		t.Fatalf("registration error: %v", err)
	}
	if !isDup {
		t.Fatalf("expected duplicate flag for existing ID %s", id1)
	}

	// 4. Test Asset ID uniqueness
	raw2, id2, err := engine.GenerateUniqueAssetID(ctx, tenantID)
	if err != nil {
		t.Fatalf("failed to generate asset ID: %v", err)
	}
	if len(raw2) != 16 || len(id2) != 23 {
		t.Fatalf("invalid generated asset ID format: %s", id2)
	}

	isRegAsset, err := engine.IsAssetIDRegistered(ctx, tenantID, id2)
	if err != nil || !isRegAsset {
		t.Fatalf("expected asset ID %s to be registered, got %v (err: %v)", id2, isRegAsset, err)
	}

	// 5. Test Non-existent ID check
	isRegRandom, err := engine.IsLocationIDRegistered(ctx, tenantID, "0NonExistentLocationID99")
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if isRegRandom {
		t.Fatalf("expected non-existent ID to return false")
	}
}
