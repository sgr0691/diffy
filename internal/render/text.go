package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sgr0691/diffy/internal/analyze"
)

// TextRenderer renders output in plain text format.
type TextRenderer struct{}

func (t TextRenderer) Render(r Result) string {
	var sb strings.Builder

	sb.WriteString("Diffy Summary\n")
	sb.WriteString(strings.Repeat("=", 40) + "\n\n")

	sb.WriteString(fmt.Sprintf("Total changes: %d\n", r.Counts.Total))
	if r.Counts.Create > 0 {
		sb.WriteString(fmt.Sprintf("  Create:  %d\n", r.Counts.Create))
	}
	if r.Counts.Update > 0 {
		sb.WriteString(fmt.Sprintf("  Update:  %d\n", r.Counts.Update))
	}
	if r.Counts.Delete > 0 {
		sb.WriteString(fmt.Sprintf("  Delete:  %d\n", r.Counts.Delete))
	}
	if r.Counts.Replace > 0 {
		sb.WriteString(fmt.Sprintf("  Replace: %d\n", r.Counts.Replace))
	}
	sb.WriteString("\n")

	if len(r.Changes) > 0 {
		sb.WriteString("Changes:\n")
		for _, ch := range r.Changes {
			sb.WriteString(fmt.Sprintf("  [%s] %s (%s)\n", ch.Action, ch.Address, ch.Type))
		}
		sb.WriteString("\n")
	}

	if len(r.Findings) > 0 {
		sb.WriteString("Findings:\n")

		sorted := make([]analyze.Finding, len(r.Findings))
		copy(sorted, r.Findings)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Severity != sorted[j].Severity {
				return sorted[i].Severity > sorted[j].Severity
			}
			return sorted[i].Address < sorted[j].Address
		})

		for _, f := range sorted {
			sb.WriteString(fmt.Sprintf("  [%s] %s — %s\n", strings.ToUpper(f.Severity.String()), f.Title, f.Address))
			sb.WriteString(fmt.Sprintf("    %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("    (action: %s, type: %s)\n\n", f.Evidence.Action, f.Evidence.ResourceType))
		}
	} else {
		sb.WriteString("No findings.\n\n")
	}

	if r.Threshold != nil {
		if r.ExitCode == 2 {
			sb.WriteString(fmt.Sprintf("FAIL: findings at or above '%s' threshold detected.\n", r.Threshold.String()))
		} else {
			sb.WriteString(fmt.Sprintf("PASS: no findings at or above '%s' threshold.\n", r.Threshold.String()))
		}
	}

	return sb.String()
}
