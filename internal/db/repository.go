package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"consteon.com/vid-generator/internal/vid"
)

const (
	CollectionVIDs = "vids"
	BatchSizeLimit = 450
)

type Repository struct {
	client *Client
}

func NewRepository(c *Client) *Repository {
	return &Repository{client: c}
}

func (r *Repository) CreateStockBatch(ctx context.Context, items []*vid.GeneratedVID, initialStatus VIDStatus) (int, int, error) {
	if len(items) == 0 {
		return 0, 0, nil
	}

	insertedCount := 0
	duplicateCount := 0
	now := time.Now().UTC()

	for i := 0; i < len(items); i += BatchSizeLimit {
		end := i + BatchSizeLimit
		if end > len(items) {
			end = len(items)
		}
		chunk := items[i:end]

		batch := r.client.Firestore.Batch()
		for _, item := range chunk {
			docID := fmt.Sprintf("%012d", item.Address.Address)
			docRef := r.client.Firestore.Collection(CollectionVIDs).Doc(docID)

			doc := VIDDocument{
				VID:       string(item.VID),
				Address:   int64(item.Address.Address),
				Cluster:   int64(item.Address.Cluster),
				Position:  int32(item.Address.Position),
				Country:   item.Country,
				Status:    initialStatus,
				CreatedAt: now,
			}
			batch.Create(docRef, doc)
		}

		_, err := batch.Commit(ctx)
		if err != nil {
			for _, item := range chunk {
				docID := fmt.Sprintf("%012d", item.Address.Address)
				docRef := r.client.Firestore.Collection(CollectionVIDs).Doc(docID)

				doc := VIDDocument{
					VID:       string(item.VID),
					Address:   int64(item.Address.Address),
					Cluster:   int64(item.Address.Cluster),
					Position:  int32(item.Address.Position),
					Country:   item.Country,
					Status:    initialStatus,
					CreatedAt: now,
				}
				_, createErr := docRef.Create(ctx, doc)
				if createErr != nil {
					if status.Code(createErr) == codes.AlreadyExists {
						duplicateCount++
					}
				} else {
					insertedCount++
				}
			}
		} else {
			insertedCount += len(chunk)
		}
	}

	return insertedCount, duplicateCount, nil
}

func (r *Repository) AllocateVIDsAtomic(ctx context.Context, countryCode string, count int, requester string) ([]*VIDDocument, error) {
	if count <= 0 {
		return nil, errors.New("allocation count must be greater than 0")
	}

	q := r.client.Firestore.Collection(CollectionVIDs).
		Where("country", "==", countryCode).
		Where("status", "==", StatusAvailable).
		Limit(count)

	iter := q.Documents(ctx)
	defer iter.Stop()

	var docRefs []*firestore.DocumentRef
	var vids []*VIDDocument

	for {
		docSnap, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to query available stock: %w", err)
		}

		var v VIDDocument
		if err := docSnap.DataTo(&v); err != nil {
			continue
		}
		docRefs = append(docRefs, docSnap.Ref)
		vids = append(vids, &v)
	}

	if len(vids) == 0 {
		return nil, fmt.Errorf("no available stock for country %s", countryCode)
	}

	now := time.Now().UTC()
	batch := r.client.Firestore.Batch()
	for _, ref := range docRefs {
		batch.Update(ref, []firestore.Update{
			{Path: "status", Value: StatusAllocated},
			{Path: "allocated_at", Value: now},
			{Path: "allocated_to", Value: requester},
		})
	}

	_, err := batch.Commit(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to commit allocation transaction: %w", err)
	}

	for _, v := range vids {
		v.Status = StatusAllocated
		v.AllocatedAt = &now
		v.AllocatedTo = requester
	}

	return vids, nil
}

func (r *Repository) GetByAddress(ctx context.Context, address int64) (*VIDDocument, error) {
	docID := fmt.Sprintf("%012d", address)
	docSnap, err := r.client.Firestore.Collection(CollectionVIDs).Doc(docID).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil
		}
		return nil, err
	}

	var doc VIDDocument
	if err := docSnap.DataTo(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (r *Repository) GetByVID(ctx context.Context, vidStr string) (*VIDDocument, error) {
	iter := r.client.Firestore.Collection(CollectionVIDs).Where("vid", "==", vidStr).Limit(1).Documents(ctx)
	defer iter.Stop()

	docSnap, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var doc VIDDocument
	if err := docSnap.DataTo(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (r *Repository) RevokeVID(ctx context.Context, vidStr string, reason string) (*VIDDocument, error) {
	doc, err := r.GetByVID(ctx, vidStr)
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, fmt.Errorf("vid %s not found", vidStr)
	}

	docID := fmt.Sprintf("%012d", doc.Address)
	now := time.Now().UTC()

	_, err = r.client.Firestore.Collection(CollectionVIDs).Doc(docID).Update(ctx, []firestore.Update{
		{Path: "status", Value: StatusRevoked},
		{Path: "revoked_at", Value: now},
		{Path: "revoke_reason", Value: reason},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to revoke vid: %w", err)
	}

	doc.Status = StatusRevoked
	doc.RevokedAt = &now
	doc.RevokeReason = reason
	return doc, nil
}

func (r *Repository) GetStockStats(ctx context.Context, countryCode string) (*StockStats, error) {
	stats := &StockStats{Country: countryCode}

	statuses := []VIDStatus{StatusAvailable, StatusAllocated, StatusInUse, StatusRevoked}
	for _, st := range statuses {
		aggQuery := r.client.Firestore.Collection(CollectionVIDs).
			Where("country", "==", countryCode).
			Where("status", "==", st).
			NewAggregationQuery().WithCount("count")

		results, err := aggQuery.Get(ctx)
		if err == nil {
			if countVal, ok := results["count"]; ok {
				if cv, ok := countVal.(*firestore.IntegerValue); ok {
					count := int(cv.Value)
					switch st {
					case StatusAvailable:
						stats.Available = count
					case StatusAllocated:
						stats.Allocated = count
					case StatusInUse:
						stats.InUse = count
					case StatusRevoked:
						stats.Revoked = count
					}
					stats.Total += count
				}
			}
		}
	}

	return stats, nil
}
