package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sgr0691/diffy/internal/analyze"
	"github.com/sgr0691/diffy/internal/parse"
	"github.com/sgr0691/diffy/internal/render"
)

var (
	flagFromPlan string
	flagFormat   string
	flagFailOn   string
)

var explainCmd = &cobra.Command{
	Use:   "explain [plan.json]",
	Short: "Explain a Terraform plan",
	Long: `Explain a Terraform plan by parsing its JSON output, analyzing changes,
and producing a human-readable summary with risk findings.

Provide either a plan JSON file as an argument, or use --from-plan to point
to a binary plan file (Diffy will run terraform show -json for you).`,
	Args: cobra.MaximumNArgs(1),
	RunE: runExplain,
}

func init() {
	explainCmd.Flags().StringVar(&flagFromPlan, "from-plan", "", "path to binary Terraform plan file (runs terraform show -json)")
	explainCmd.Flags().StringVar(&flagFormat, "format", "md", "output format: md, text, or json")
	explainCmd.Flags().StringVar(&flagFailOn, "fail-on", "", "exit 2 if findings at or above this severity: info, low, medium, high, critical")

	rootCmd.AddCommand(explainCmd)
}

func runExplain(cmd *cobra.Command, args []string) error {
	// Validate input: exactly one of plan.json arg or --from-plan
	hasArg := len(args) == 1
	hasPlan := flagFromPlan != ""

	if !hasArg && !hasPlan {
		return fmt.Errorf("provide a plan JSON file as an argument, or use --from-plan <plan.out>\n\nUsage: diffy explain <plan.json>\n       diffy explain --from-plan <plan.out>")
	}
	if hasArg && hasPlan {
		return fmt.Errorf("provide either a plan JSON file argument or --from-plan, not both")
	}

	// Validate format
	if flagFormat != "md" && flagFormat != "text" && flagFormat != "json" {
		return fmt.Errorf("invalid format %q: must be md, text, or json", flagFormat)
	}

	// Parse threshold
	var threshold *analyze.Severity
	if flagFailOn != "" {
		sev, ok := analyze.ParseSeverity(flagFailOn)
		if !ok {
			return fmt.Errorf("invalid --fail-on value %q: must be info, low, medium, high, or critical", flagFailOn)
		}
		threshold = &sev
	}

	// Load changes
	var changes []parse.ResourceChange
	var err error

	if hasPlan {
		changes, err = parse.FromPlanBinary(flagFromPlan)
	} else {
		changes, err = parse.FromFile(args[0])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Compute counts
	counts := parse.ComputeCounts(changes)

	// Analyze
	findings := analyze.Analyze(changes)

	// Determine exit code
	exitCode := 0
	if threshold != nil && analyze.ExceedsThreshold(findings, *threshold) {
		exitCode = 2
	}

	// Render
	result := render.Result{
		Counts:    counts,
		Changes:   changes,
		Findings:  findings,
		Threshold: threshold,
		ExitCode:  exitCode,
	}

	var renderer render.Renderer
	switch flagFormat {
	case "text":
		renderer = render.TextRenderer{}
	case "json":
		renderer = render.JSONRenderer{}
	default:
		renderer = render.MarkdownRenderer{}
	}

	fmt.Print(renderer.Render(result))
	os.Exit(exitCode)
	return nil
}
