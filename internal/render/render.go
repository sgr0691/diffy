package render

import (
	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
)

// Result holds all data needed for rendering.
type Result struct {
	Counts    parse.Counts
	Changes   []parse.ResourceChange
	Findings  []analyze.Finding
	Threshold *analyze.Severity // nil if --fail-on not set
	ExitCode  int
}

// Renderer renders a Result to a string.
type Renderer interface {
	Render(r Result) string
}
