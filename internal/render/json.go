package render

import (
	"encoding/json"

	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
)

// JSONRenderer renders output in JSON format.
type JSONRenderer struct{}

type jsonOutput struct {
	Counts    parse.Counts  `json:"counts"`
	Changes   []jsonChange  `json:"changes"`
	Findings  []jsonFinding `json:"findings"`
	Threshold *string       `json:"threshold,omitempty"`
	Decision  string        `json:"decision"`
	ExitCode  int           `json:"exit_code"`
}

type jsonChange struct {
	Address      string   `json:"address"`
	Type         string   `json:"type"`
	ProviderName string   `json:"provider_name,omitempty"`
	Action       string   `json:"action"`
	ChangePaths  []string `json:"change_paths,omitempty"`
}

type jsonFinding struct {
	Severity     string   `json:"severity"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Address      string   `json:"resource_address"`
	Action       string   `json:"action"`
	ResourceType string   `json:"resource_type"`
	ChangePaths  []string `json:"change_paths,omitempty"`
	Matches      []string `json:"matches,omitempty"`
}

func (j JSONRenderer) Render(r Result) string {
	changes := make([]jsonChange, len(r.Changes))
	for i, ch := range r.Changes {
		changes[i] = jsonChange{
			Address:      ch.Address,
			Type:         ch.Type,
			ProviderName: ch.ProviderName,
			Action:       string(ch.Action),
			ChangePaths:  ch.ChangePaths,
		}
	}

	findings := make([]jsonFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = jsonFinding{
			Severity:     f.Severity.String(),
			Title:        f.Title,
			Description:  f.Description,
			Address:      f.Address,
			Action:       string(f.Evidence.Action),
			ResourceType: f.Evidence.ResourceType,
			ChangePaths:  f.Evidence.ChangePaths,
			Matches:      f.Evidence.Matches,
		}
	}

	decision := "pass"
	if r.ExitCode == 2 {
		decision = "fail"
	}

	out := jsonOutput{
		Counts:   r.Counts,
		Changes:  changes,
		Findings: findings,
		Decision: decision,
		ExitCode: r.ExitCode,
	}

	if r.Threshold != nil {
		s := r.Threshold.String()
		out.Threshold = &s
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return `{"error": "failed to marshal output"}`
	}
	return string(data) + "\n"
}

// SortFindings sorts findings by severity (highest first), then by address.
func SortFindings(findings []analyze.Finding) []analyze.Finding {
	sorted := make([]analyze.Finding, len(findings))
	copy(sorted, findings)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Severity > sorted[i].Severity ||
				(sorted[j].Severity == sorted[i].Severity && sorted[j].Address < sorted[i].Address) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}
