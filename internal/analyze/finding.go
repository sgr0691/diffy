package analyze

import "github.com/sgr0691/diffy/internal/parse"

// Finding represents a single risk finding from the analysis.
type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Address     string   `json:"resource_address"`
	Evidence    Evidence `json:"evidence"`
}

// Evidence captures supporting data for a finding.
type Evidence struct {
	Action       parse.Action `json:"action"`
	ResourceType string       `json:"resource_type"`
	ChangePaths  []string     `json:"change_paths,omitempty"`
	Matches      []string     `json:"matches,omitempty"`
}
