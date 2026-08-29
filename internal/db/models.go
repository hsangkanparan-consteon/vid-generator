package db

import (
	"time"
)

type VIDStatus string

const (
	StatusAvailable VIDStatus = "available"
	StatusAllocated VIDStatus = "allocated"
	StatusInUse     VIDStatus = "in_use"
	StatusRevoked   VIDStatus = "revoked"
)

type VIDDocument struct {
	VID                string    `firestore:"vid" json:"vid"`
	Address            int64     `firestore:"address" json:"address"`
	Cluster            int64     `firestore:"cluster" json:"cluster"`
	Position           int32     `firestore:"position" json:"position"`
	Country            string    `firestore:"country" json:"country"`
	Status             VIDStatus `firestore:"status" json:"status"`
	CreatedAt          time.Time `firestore:"created_at" json:"created_at"`
	AllocatedAt        *time.Time `firestore:"allocated_at,omitempty" json:"allocated_at,omitempty"`
	AllocatedTo        string    `firestore:"allocated_to,omitempty" json:"allocated_to,omitempty"`
	AssignedEntityType string    `firestore:"assigned_entity_type,omitempty" json:"assigned_entity_type,omitempty"`
	AssignedEntityID   string    `firestore:"assigned_entity_id,omitempty" json:"assigned_entity_id,omitempty"`
	ActivatedAt        *time.Time `firestore:"activated_at,omitempty" json:"activated_at,omitempty"`
	RevokedAt          *time.Time `firestore:"revoked_at,omitempty" json:"revoked_at,omitempty"`
	RevokeReason       string    `firestore:"revoke_reason,omitempty" json:"revoke_reason,omitempty"`
}

type StockStats struct {
	Country   string `json:"country"`
	Available int    `json:"available"`
	Allocated int    `json:"allocated"`
	InUse     int    `json:"in_use"`
	Revoked   int    `json:"revoked"`
	Total     int    `json:"total"`
}
