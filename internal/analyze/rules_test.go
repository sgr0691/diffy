package analyze

import (
	"encoding/json"
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

func TestPublicIngressDetection(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_security_group.web",
			Type:    "aws_security_group",
			Action:  parse.ActionUpdate,
			After: mustRawJSON(t, map[string]any{
				"ingress": []any{
					map[string]any{
						"from_port":   22,
						"to_port":     22,
						"protocol":    "tcp",
						"cidr_blocks": []any{"0.0.0.0/0"},
					},
				},
			}),
			ChangePaths: []string{"ingress[0].cidr_blocks[0]", "ingress[0].from_port", "ingress[0].to_port"},
		},
	}

	findings := Analyze(changes)
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding")
	}
	if findings[0].Severity != SeverityHigh {
		t.Fatalf("expected high severity, got %s", findings[0].Severity)
	}
	if findings[0].Title != "Public ingress exposure detected" {
		t.Fatalf("unexpected title: %s", findings[0].Title)
	}
}

func TestInternetFacingLoadBalancerDetection(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_lb.public",
			Type:    "aws_lb",
			Action:  parse.ActionCreate,
			After: mustRawJSON(t, map[string]any{
				"scheme": "internet-facing",
			}),
			ChangePaths: []string{"scheme"},
		},
	}
	findings := Analyze(changes)
	if !hasFindingTitle(findings, "Internet-facing load balancer detected") {
		t.Fatalf("expected internet-facing LB finding, got %#v", findings)
	}
}

func TestPublicIPAssociationDetection(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_instance.web",
			Type:    "aws_instance",
			Action:  parse.ActionUpdate,
			After: mustRawJSON(t, map[string]any{
				"associate_public_ip_address": true,
			}),
			ChangePaths: []string{"associate_public_ip_address"},
		},
	}
	findings := Analyze(changes)
	if !hasFindingTitle(findings, "Public IP association enabled") {
		t.Fatalf("expected public IP finding, got %#v", findings)
	}
}

func TestIAMAttachmentAndPolicyDocDetection(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_iam_role_policy_attachment.app",
			Type:    "aws_iam_role_policy_attachment",
			Action:  parse.ActionCreate,
			After:   mustRawJSON(t, map[string]any{"role": "app-role", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
			ChangePaths: []string{
				"role",
				"policy_arn",
			},
		},
		{
			Address: "aws_iam_policy.custom",
			Type:    "aws_iam_policy",
			Action:  parse.ActionUpdate,
			Before:  mustRawJSON(t, map[string]any{"policy": "{\"Version\":\"2012-10-17\"}"}),
			After:   mustRawJSON(t, map[string]any{"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"}),
			ChangePaths: []string{
				"policy",
			},
		},
	}

	findings := Analyze(changes)
	if !hasFindingTitle(findings, "IAM policy attachment change detected") {
		t.Fatalf("expected IAM attachment finding, got %#v", findings)
	}
	if !hasFindingTitle(findings, "IAM policy document change detected") {
		t.Fatalf("expected IAM policy document finding, got %#v", findings)
	}
}

func TestStatefulImpactfulUpdateAndTagOnly(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address:     "aws_db_instance.main",
			Type:        "aws_db_instance",
			Action:      parse.ActionUpdate,
			ChangePaths: []string{"allocated_storage"},
		},
		{
			Address:     "aws_instance.web",
			Type:        "aws_instance",
			Action:      parse.ActionUpdate,
			ChangePaths: []string{"tags.env"},
		},
	}
	findings := Analyze(changes)
	if !hasFindingTitle(findings, "Impactful stateful update detected") {
		t.Fatalf("expected stateful update finding, got %#v", findings)
	}
	if !hasFindingTitle(findings, "Tag-only update detected") {
		t.Fatalf("expected tag-only finding, got %#v", findings)
	}
}

func TestNetworkRoutingChangeDetection(t *testing.T) {
	changes := []parse.ResourceChange{
		{
			Address: "aws_route.private_default",
			Type:    "aws_route",
			Action:  parse.ActionUpdate,
		},
	}
	findings := Analyze(changes)
	if !hasFindingTitle(findings, "Network routing change detected") {
		t.Fatalf("expected routing finding, got %#v", findings)
	}
}

func hasFindingTitle(findings []Finding, title string) bool {
	for _, f := range findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

func mustRawJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal raw json: %v", err)
	}
	return b
}
