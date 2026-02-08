package analyze

import (
	"testing"

	"github.com/sgr0691/diffy/internal/parse"
)

func TestActionMappingReplace(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_instance.web",
			Type:    "aws_instance",
			Action:  parse.ActionReplace,
		},
	}
	findings := Analyze(changes)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityHigh {
		t.Errorf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "Resource replacement detected" {
		t.Errorf("unexpected title: %s", findings[0].Title)
	}
}

func TestDeleteStatefulIsCritical(t *testing.T) {
	tests := []struct {
		name         string
		resourceType string
		wantSeverity Severity
	}{
		{"aws_db_instance delete", "aws_db_instance", SeverityCritical},
		{"aws_rds_cluster delete", "aws_rds_cluster", SeverityCritical},
		{"aws_rds_cluster_instance delete", "aws_rds_cluster_instance", SeverityCritical},
		{"aws_s3_bucket delete", "aws_s3_bucket", SeverityCritical},
		{"aws_eks_cluster delete", "aws_eks_cluster", SeverityCritical},
		{"aws_elasticache_cluster delete (prefix)", "aws_elasticache_cluster", SeverityCritical},
		{"aws_elasticache_replication_group delete (prefix)", "aws_elasticache_replication_group", SeverityCritical},
		{"aws_efs_file_system delete (prefix)", "aws_efs_file_system", SeverityCritical},
		{"aws_instance delete (not stateful)", "aws_instance", SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := []parse.ResourceChange{
				{
					Address: "test." + tt.resourceType,
					Type:    tt.resourceType,
					Action:  parse.ActionDelete,
				},
			}
			findings := Analyze(changes)
			if len(findings) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(findings))
			}
			if findings[0].Severity != tt.wantSeverity {
				t.Errorf("expected %s severity, got %s", tt.wantSeverity, findings[0].Severity)
			}
		})
	}
}

func TestReplaceStatefulIsCritical(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_db_instance.main",
			Type:    "aws_db_instance",
			Action:  parse.ActionReplace,
		},
	}
	findings := Analyze(changes)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected critical severity for stateful replace, got %s", findings[0].Severity)
	}
}

func TestCreateAndUpdateProduceNoFindings(t *testing.T) {
	changes := []parse.ResourceChange{
		{Address: "aws_instance.a", Type: "aws_instance", Action: parse.ActionCreate},
		{Address: "aws_instance.b", Type: "aws_instance", Action: parse.ActionUpdate},
	}
	findings := Analyze(changes)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for create/update, got %d", len(findings))
	}
}

func TestExceedsThreshold(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityHigh, Title: "test"},
	}

	if !ExceedsThreshold(findings, SeverityHigh) {
		t.Error("high finding should exceed high threshold")
	}
	if !ExceedsThreshold(findings, SeverityMedium) {
		t.Error("high finding should exceed medium threshold")
	}
	if ExceedsThreshold(findings, SeverityCritical) {
		t.Error("high finding should not exceed critical threshold")
	}
}

func TestFailOnThresholdExitCode(t *testing.T) {
	// Simulate what the CLI does: check findings against threshold
	findings := []Finding{
		{Severity: SeverityHigh, Title: "Replace detected", Address: "aws_instance.web"},
		{Severity: SeverityCritical, Title: "Stateful delete", Address: "aws_db_instance.main"},
	}

	// --fail-on high: should fail (exit 2)
	if !ExceedsThreshold(findings, SeverityHigh) {
		t.Error("expected threshold exceeded for high")
	}

	// --fail-on critical: should fail (exit 2)
	if !ExceedsThreshold(findings, SeverityCritical) {
		t.Error("expected threshold exceeded for critical")
	}

	// No critical findings: should pass
	highOnly := []Finding{
		{Severity: SeverityHigh, Title: "Replace detected"},
	}
	if ExceedsThreshold(highOnly, SeverityCritical) {
		t.Error("high-only findings should not exceed critical threshold")
	}
}

func TestMaxSeverity(t *testing.T) {
	findings := []Finding{
		{Severity: SeverityLow},
		{Severity: SeverityHigh},
		{Severity: SeverityMedium},
	}
	if MaxSeverity(findings) != SeverityHigh {
		t.Errorf("expected high, got %s", MaxSeverity(findings))
	}

	if MaxSeverity(nil) != SeverityInfo {
		t.Errorf("expected info for empty findings, got %s", MaxSeverity(nil))
	}
}
