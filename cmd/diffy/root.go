package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

var rootCmd = &cobra.Command{
	Use:   "diffy",
	Short: "Explain infrastructure diffs in plain English",
	Long: `Diffy turns Terraform plan output into a human-readable summary
with risk flags, so reviewers can quickly answer:
"What's changing, and how risky is it?"`,
	Version: version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
