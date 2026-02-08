package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
)

func TestGoldenMarkdown(t *testing.T) {
	tests := []struct {
		name     string
		planFile string
		goldFile string
	}{
		{"replace", "replace.json", "replace.md"},
		{"delete_stateful", "delete_stateful.json", "delete_stateful.md"},
		{"benign_tags_only", "benign_tags_only.json", "benign_tags_only.md"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			planPath := filepath.Join("..", "..", "examples", "plan", tt.planFile)
			goldPath := filepath.Join("..", "..", "examples", "expected", tt.goldFile)

			changes, err := parse.FromFile(planPath)
			if err != nil {
				t.Fatal(err)
			}

			counts := parse.ComputeCounts(changes)
			findings := analyze.Analyze(changes)

			result := Result{
				Counts:   counts,
				Changes:  changes,
				Findings: findings,
			}

			renderer := MarkdownRenderer{}
			got := renderer.Render(result)

			expected, err := os.ReadFile(goldPath)
			if err != nil {
				t.Fatal(err)
			}

			gotNorm := normalizeWhitespace(got)
			expNorm := normalizeWhitespace(string(expected))

			if gotNorm != expNorm {
				t.Errorf("golden mismatch for %s\n--- got ---\n%s\n--- expected ---\n%s", tt.name, got, string(expected))
			}
		})
	}
}

func TestJSONRenderer(t *testing.T) {
	changes := []parse.ResourceChange{
		{Address: "aws_instance.web", Type: "aws_instance", Action: parse.ActionReplace},
	}
	findings := []analyze.Finding{
		{
			Severity:    analyze.SeverityHigh,
			Title:       "Resource replacement detected",
			Description: "Resource aws_instance.web will be replaced.",
			Address:     "aws_instance.web",
			Evidence:    analyze.Evidence{Action: parse.ActionReplace, ResourceType: "aws_instance"},
		},
	}
	threshold := analyze.SeverityHigh
	result := Result{
		Counts:    parse.Counts{Replace: 1, Total: 1},
		Changes:   changes,
		Findings:  findings,
		Threshold: &threshold,
		ExitCode:  2,
	}

	renderer := JSONRenderer{}
	output := renderer.Render(result)

	if !strings.Contains(output, `"decision": "fail"`) {
		t.Error("expected decision: fail in JSON output")
	}
	if !strings.Contains(output, `"severity": "high"`) {
		t.Error("expected severity: high in JSON output")
	}
	if !strings.Contains(output, `"threshold": "high"`) {
		t.Error("expected threshold: high in JSON output")
	}
}

func TestTextRenderer(t *testing.T) {
	changes := []parse.ResourceChange{
		{Address: "aws_instance.web", Type: "aws_instance", Action: parse.ActionUpdate},
	}
	result := Result{
		Counts:  parse.Counts{Update: 1, Total: 1},
		Changes: changes,
	}

	renderer := TextRenderer{}
	output := renderer.Render(result)

	if !strings.Contains(output, "Total changes: 1") {
		t.Error("expected 'Total changes: 1' in text output")
	}
	if !strings.Contains(output, "No findings.") {
		t.Error("expected 'No findings.' in text output")
	}
}

func normalizeWhitespace(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	return strings.Join(lines, "\n")
}
