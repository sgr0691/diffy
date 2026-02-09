package parse

import "encoding/json"

// Action represents a normalized Terraform change action.
type Action string

const (
	ActionCreate  Action = "create"
	ActionUpdate  Action = "update"
	ActionDelete  Action = "delete"
	ActionReplace Action = "replace"
	ActionNoop    Action = "no-op"
)

// ResourceChange is a normalized representation of a single Terraform resource change.
type ResourceChange struct {
	Address      string          `json:"address"`
	Type         string          `json:"type"`
	ProviderName string          `json:"provider_name,omitempty"`
	Action       Action          `json:"action"`
	Before       json.RawMessage `json:"before,omitempty"`
	After        json.RawMessage `json:"after,omitempty"`
	ChangePaths  []string        `json:"change_paths,omitempty"`
}

// Counts holds aggregate counts by action type.
type Counts struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Delete  int `json:"delete"`
	Replace int `json:"replace"`
	Total   int `json:"total"`
}
