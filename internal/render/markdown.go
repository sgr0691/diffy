package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
)

// MarkdownRenderer renders output in Markdown format.
type MarkdownRenderer struct{}

func (m MarkdownRenderer) Render(r Result) string {
	var sb strings.Builder

	// Header summary
	sb.WriteString("# Diffy Summary\n\n")
	sb.WriteString(fmt.Sprintf("**%d** total changes: ", r.Counts.Total))
	parts := []string{}
	if r.Counts.Create > 0 {
		parts = append(parts, fmt.Sprintf("%d to create", r.Counts.Create))
	}
	if r.Counts.Update > 0 {
		parts = append(parts, fmt.Sprintf("%d to update", r.Counts.Update))
	}
	if r.Counts.Delete > 0 {
		parts = append(parts, fmt.Sprintf("%d to delete", r.Counts.Delete))
	}
	if r.Counts.Replace > 0 {
		parts = append(parts, fmt.Sprintf("%d to replace", r.Counts.Replace))
	}
	if len(parts) == 0 {
		parts = append(parts, "no changes")
	}
	sb.WriteString(strings.Join(parts, ", "))
	sb.WriteString("\n\n")

	// Top changes table
	if len(r.Changes) > 0 {
		summaries := summarizeChangeFindings(r.Changes, r.Findings)
		sb.WriteString("## Changes\n\n")
		sb.WriteString("| Action | Resource | Severity | Notes |\n")
		sb.WriteString("|--------|----------|----------|-------|\n")
		for _, ch := range r.Changes {
			summary := summaries[ch.Address]
			sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", ch.Action, ch.Address, summary.Severity, summary.Notes))
		}
		sb.WriteString("\n")
	}

	// Findings grouped by severity (highest first)
	if len(r.Findings) > 0 {
		sb.WriteString("## Findings\n\n")

		grouped := groupBySeverity(r.Findings)
		order := []analyze.Severity{
			analyze.SeverityCritical,
			analyze.SeverityHigh,
			analyze.SeverityMedium,
			analyze.SeverityLow,
			analyze.SeverityInfo,
		}

		for _, sev := range order {
			findings, ok := grouped[sev]
			if !ok {
				continue
			}
			sb.WriteString(fmt.Sprintf("### %s\n\n", strings.ToUpper(sev.String())))
			for _, f := range findings {
				sb.WriteString(fmt.Sprintf("- **%s** — `%s`\n", f.Title, f.Address))
				sb.WriteString(fmt.Sprintf("  %s\n", f.Description))
				sb.WriteString(fmt.Sprintf("  _(action: %s, type: %s)_\n\n", f.Evidence.Action, f.Evidence.ResourceType))
			}
		}
	} else {
		sb.WriteString("No findings.\n")
	}

	// Threshold decision
	if r.Threshold != nil {
		sb.WriteString("---\n\n")
		if r.ExitCode == 2 {
			sb.WriteString(fmt.Sprintf("**FAIL**: findings at or above `%s` threshold detected.\n", r.Threshold.String()))
		} else {
			sb.WriteString(fmt.Sprintf("**PASS**: no findings at or above `%s` threshold.\n", r.Threshold.String()))
		}
	}

	return sb.String()
}

func groupBySeverity(findings []analyze.Finding) map[analyze.Severity][]analyze.Finding {
	m := make(map[analyze.Severity][]analyze.Finding)
	// Sort findings within each severity by address for stability
	sorted := make([]analyze.Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address < sorted[j].Address
	})
	for _, f := range sorted {
		m[f.Severity] = append(m[f.Severity], f)
	}
	return m
}

type changeSummary struct {
	Severity string
	Notes    string
}

func summarizeChangeFindings(changes []parse.ResourceChange, findings []analyze.Finding) map[string]changeSummary {
	out := make(map[string]changeSummary, len(changes))
	for _, ch := range changes {
		out[ch.Address] = changeSummary{
			Severity: "-",
			Notes:    ch.Type,
		}
	}

	byAddress := make(map[string][]analyze.Finding)
	for _, f := range findings {
		byAddress[f.Address] = append(byAddress[f.Address], f)
	}

	for _, ch := range changes {
		fs := byAddress[ch.Address]
		if len(fs) == 0 {
			continue
		}
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].Severity != fs[j].Severity {
				return fs[i].Severity > fs[j].Severity
			}
			return fs[i].Title < fs[j].Title
		})
		out[ch.Address] = changeSummary{
			Severity: strings.ToUpper(fs[0].Severity.String()),
			Notes:    fs[0].Title,
		}
	}

	return out
}
