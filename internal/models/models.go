package models

import "time"

type Session struct {
	ID          string
	TargetLabel string
	StartedAt   time.Time
	ClosedAt    *time.Time
}

type Evidence struct {
	ID           string
	EventID      *string
	RawOutputRef string
	ToolName     string
	ParseLevel   int
	CreatedAt    time.Time
}

type Observation struct {
	ID         string
	EvidenceID string
	Kind       string
	Payload    map[string]any
	Confidence float64
	Status     string
}

type Entity struct {
	ID             string
	SessionID      string
	Type           string
	CanonicalValue string
	Attrs          map[string]any
	FirstSeen      time.Time
	LastSeen       time.Time
}

type Relationship struct {
	ID                       string
	SourceEntityID           string
	TargetEntityID           string
	Kind                     string
	Confidence               float64
	SupportingObservationID  *string
	ValidFrom                time.Time
	ValidTo                  *time.Time
}

type MethodologyObjective struct {
	ID              string
	SessionID       string
	IntentKey       string
	TriggerEntityID string
	Status          string
	CreatedAt       time.Time
}

type ObjectivePath struct {
	ID           string
	ObjectiveID  string
	PathKey      string
	Description  string
	Status       string
	CreatedAt    time.Time
}

type Candidate struct {
	ID                       string
	SessionID                string
	Source                   string
	ObjectivePathID          *string
	IntentKey                string
	Parameters               map[string]any
	Tool                     string
	CommandTemplateRendered  string
	Score                    float64
	ScoreTerms               map[string]float64
	Explanation              string
	CreatedAt                time.Time
	Status                   string
}

type Action struct {
	ID              string
	CandidateID     string
	ObjectivePathID *string
	ExecutedAt      time.Time
}

type Outcome struct {
	ID                       string
	ActionID                 string
	NewEntities              int
	NewRelationships         int
	HypothesesConfirmed      int
	HypothesesRefuted        int
	ContradictionsResolved   int
	ComputedInformationGain  float64
	RecordedAt               time.Time
}
