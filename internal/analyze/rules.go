package analyze

import (
	"fmt"
	"strings"

	"github.com/sgr0691/diffy/internal/parse"
)

// statefulTypes is the starter list of AWS stateful resource types where
// deletes are especially dangerous.
var statefulTypes = map[string]bool{
	"aws_db_instance":         true,
	"aws_rds_cluster":         true,
	"aws_rds_cluster_instance": true,
	"aws_s3_bucket":           true,
	"aws_eks_cluster":         true,
}

// statefulPrefixes are prefix-matched stateful resource types.
var statefulPrefixes = []string{
	"aws_elasticache_",
	"aws_efs_",
}

func isStateful(resourceType string) bool {
	if statefulTypes[resourceType] {
		return true
	}
	for _, prefix := range statefulPrefixes {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

// Analyze runs all v0.1 rules against the given resource changes and returns findings.
func Analyze(changes []parse.ResourceChange) []Finding {
	var findings []Finding

	for _, ch := range changes {
		findings = append(findings, analyzeChange(ch)...)
	}

	return findings
}

func analyzeChange(ch parse.ResourceChange) []Finding {
	var findings []Finding

	switch ch.Action {
	case parse.ActionReplace:
		sev := SeverityHigh
		desc := fmt.Sprintf("Resource %s will be replaced (destroyed and recreated). This may cause downtime or data loss.", ch.Address)
		if isStateful(ch.Type) {
			sev = SeverityCritical
			desc = fmt.Sprintf("Stateful resource %s will be replaced (destroyed and recreated). This will likely cause data loss.", ch.Address)
		}
		findings = append(findings, Finding{
			Severity:    sev,
			Title:       "Resource replacement detected",
			Description: desc,
			Address:     ch.Address,
			Evidence: Evidence{
				Action:       ch.Action,
				ResourceType: ch.Type,
			},
		})

	case parse.ActionDelete:
		sev := SeverityHigh
		desc := fmt.Sprintf("Resource %s will be deleted.", ch.Address)
		if isStateful(ch.Type) {
			sev = SeverityCritical
			desc = fmt.Sprintf("Stateful resource %s will be deleted. This will likely cause data loss.", ch.Address)
		}
		findings = append(findings, Finding{
			Severity:    sev,
			Title:       "Resource deletion detected",
			Description: desc,
			Address:     ch.Address,
			Evidence: Evidence{
				Action:       ch.Action,
				ResourceType: ch.Type,
			},
		})
	}

	return findings
}

// MaxSeverity returns the highest severity among findings, or SeverityInfo if empty.
func MaxSeverity(findings []Finding) Severity {
	max := SeverityInfo
	for _, f := range findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// ExceedsThreshold returns true if any finding meets or exceeds the given threshold.
func ExceedsThreshold(findings []Finding, threshold Severity) bool {
	for _, f := range findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}
