package render

import (
	"encoding/json"

	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
)

// JSONRenderer renders output in JSON format.
type JSONRenderer struct{}

type jsonOutput struct {
	Counts    parse.Counts     `json:"counts"`
	Findings  []jsonFinding    `json:"findings"`
	Threshold *string          `json:"threshold,omitempty"`
	Decision  string           `json:"decision"`
}

type jsonFinding struct {
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
	Address      string `json:"resource_address"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
}

func (j JSONRenderer) Render(r Result) string {
	findings := make([]jsonFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = jsonFinding{
			Severity:     f.Severity.String(),
			Title:        f.Title,
			Description:  f.Description,
			Address:      f.Address,
			Action:       string(f.Evidence.Action),
			ResourceType: f.Evidence.ResourceType,
		}
	}

	decision := "pass"
	if r.ExitCode == 2 {
		decision = "fail"
	}

	out := jsonOutput{
		Counts:   r.Counts,
		Findings: findings,
		Decision: decision,
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
