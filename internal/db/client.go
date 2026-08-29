package db

import (
	"context"
	"fmt"

	"cloud.google.com/go/firestore"
)

type Client struct {
	Firestore *firestore.Client
	ProjectID string
	Database  string
}

func NewClient(ctx context.Context, projectID, databaseID string) (*Client, error) {
	if projectID == "" {
		return nil, fmt.Errorf("projectID cannot be empty")
	}
	if databaseID == "" {
		databaseID = "(default)"
	}

	var fsClient *firestore.Client
	var err error

	if databaseID == "(default)" {
		fsClient, err = firestore.NewClient(ctx, projectID)
	} else {
		fsClient, err = firestore.NewClientWithDatabase(ctx, projectID, databaseID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client for db '%s' in project '%s': %w", databaseID, projectID, err)
	}

	return &Client{
		Firestore: fsClient,
		ProjectID: projectID,
		Database:  databaseID,
	}, nil
}

func (c *Client) Close() error {
	if c.Firestore != nil {
		return c.Firestore.Close()
	}
	return nil
}
