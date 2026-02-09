package analyze

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/sgr0691/diffy/internal/parse"
)

// statefulTypes is the starter list of AWS stateful resource types where
// deletes are especially dangerous.
var statefulTypes = map[string]bool{
	"aws_db_instance":          true,
	"aws_rds_cluster":          true,
	"aws_rds_cluster_instance": true,
	"aws_s3_bucket":            true,
	"aws_eks_cluster":          true,
}

// statefulPrefixes are prefix-matched stateful resource types.
var statefulPrefixes = []string{
	"aws_elasticache_",
	"aws_efs_",
}

var iamAttachmentTypes = map[string]bool{
	"aws_iam_group_policy_attachment": true,
	"aws_iam_policy_attachment":       true,
	"aws_iam_role_policy_attachment":  true,
	"aws_iam_user_policy_attachment":  true,
}

var iamPolicyDocTypes = map[string]bool{
	"aws_iam_group_policy": true,
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_user_policy":  true,
}

var publicCommonPorts = []int{22, 80, 443, 3389, 3306, 5432, 6379}

var statefulImpactfulPathHints = []string{
	"allocated_storage",
	"storage_type",
	"engine_version",
	"instance_class",
	"storage_encrypted",
	"kms_key_id",
	"encrypted",
	"snapshot_retention_limit",
}

var networkRoutingTypes = map[string]bool{
	"aws_internet_gateway":        true,
	"aws_nat_gateway":             true,
	"aws_route":                   true,
	"aws_route_table":             true,
	"aws_route_table_association": true,
	"aws_vpn_gateway":             true,
}

var networkRoutingPrefixes = []string{
	"aws_ec2_transit_gateway",
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
		findings = append(findings, newFinding(sev, "Resource replacement detected", desc, ch, ch.ChangePaths, nil))

	case parse.ActionDelete:
		sev := SeverityHigh
		desc := fmt.Sprintf("Resource %s will be deleted.", ch.Address)
		if isStateful(ch.Type) {
			sev = SeverityCritical
			desc = fmt.Sprintf("Stateful resource %s will be deleted. This will likely cause data loss.", ch.Address)
		}
		findings = append(findings, newFinding(sev, "Resource deletion detected", desc, ch, ch.ChangePaths, nil))
	}

	findings = append(findings, analyzePublicExposure(ch)...)
	findings = append(findings, analyzeIAM(ch)...)
	findings = append(findings, analyzeUpdateRisk(ch)...)

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

func analyzePublicExposure(ch parse.ResourceChange) []Finding {
	if ch.Action != parse.ActionCreate && ch.Action != parse.ActionUpdate && ch.Action != parse.ActionReplace {
		return nil
	}

	var findings []Finding

	if matches := findPublicIngress(ch); len(matches) > 0 {
		findings = append(findings, newFinding(
			SeverityHigh,
			"Public ingress exposure detected",
			fmt.Sprintf("Resource %s allows ingress from public CIDR ranges on commonly targeted ports.", ch.Address),
			ch,
			filterPaths(ch.ChangePaths, []string{"ingress", "cidr", "port", "protocol", "security_group"}),
			matches,
		))
	}

	if isInternetFacingLB(ch) {
		findings = append(findings, newFinding(
			SeverityHigh,
			"Internet-facing load balancer detected",
			fmt.Sprintf("Load balancer %s is configured as internet-facing.", ch.Address),
			ch,
			filterPaths(ch.ChangePaths, []string{"scheme", "internal"}),
			[]string{"scheme=internet-facing"},
		))
	}

	if hasPublicIPEnabled(ch) {
		findings = append(findings, newFinding(
			SeverityHigh,
			"Public IP association enabled",
			fmt.Sprintf("Resource %s enables public IP association.", ch.Address),
			ch,
			filterPaths(ch.ChangePaths, []string{"public_ip", "associate_public_ip_address", "map_public_ip_on_launch"}),
			[]string{"public_ip=true"},
		))
	}

	return findings
}

func analyzeIAM(ch parse.ResourceChange) []Finding {
	if !strings.HasPrefix(ch.Type, "aws_iam_") {
		return nil
	}
	if ch.Action == parse.ActionDelete {
		return nil
	}

	var findings []Finding

	if iamAttachmentTypes[ch.Type] {
		findings = append(findings, newFinding(
			SeverityHigh,
			"IAM policy attachment change detected",
			fmt.Sprintf("IAM attachment resource %s is being created or modified.", ch.Address),
			ch,
			filterPaths(ch.ChangePaths, []string{"policy", "role", "group", "user"}),
			[]string{ch.Type},
		))
	}

	if iamPolicyDocTypes[ch.Type] || hasPathHint(ch.ChangePaths, []string{"policy", "assume_role_policy", "inline_policy"}) {
		if ch.Action == parse.ActionCreate || ch.Action == parse.ActionUpdate || ch.Action == parse.ActionReplace {
			findings = append(findings, newFinding(
				SeverityHigh,
				"IAM policy document change detected",
				fmt.Sprintf("Policy document fields changed for %s. Review policy scope carefully.", ch.Address),
				ch,
				filterPaths(ch.ChangePaths, []string{"policy", "assume_role_policy", "inline_policy"}),
				nil,
			))
		}
	}

	return dedupeFindings(findings)
}

func analyzeUpdateRisk(ch parse.ResourceChange) []Finding {
	if ch.Action != parse.ActionUpdate && ch.Action != parse.ActionCreate && ch.Action != parse.ActionReplace {
		return nil
	}

	var findings []Finding
	if ch.Action == parse.ActionUpdate && isTagOnlyChange(ch.ChangePaths) {
		findings = append(findings, newFinding(
			SeverityLow,
			"Tag-only update detected",
			fmt.Sprintf("Resource %s only changed tags.", ch.Address),
			ch,
			filterPaths(ch.ChangePaths, []string{"tags", "tags_all"}),
			nil,
		))
	}

	if ch.Action == parse.ActionUpdate && isStateful(ch.Type) {
		matched := filterPaths(ch.ChangePaths, statefulImpactfulPathHints)
		if len(matched) > 0 {
			findings = append(findings, newFinding(
				SeverityMedium,
				"Impactful stateful update detected",
				fmt.Sprintf("Stateful resource %s has impactful configuration updates.", ch.Address),
				ch,
				matched,
				nil,
			))
		}
	}

	if isNetworkRoutingType(ch.Type) {
		findings = append(findings, newFinding(
			SeverityMedium,
			"Network routing change detected",
			fmt.Sprintf("Resource %s changes network routing/gateway behavior.", ch.Address),
			ch,
			ch.ChangePaths,
			nil,
		))
	}

	return dedupeFindings(findings)
}

func newFinding(severity Severity, title, description string, ch parse.ResourceChange, changePaths, matches []string) Finding {
	return Finding{
		Severity:    severity,
		Title:       title,
		Description: description,
		Address:     ch.Address,
		Evidence: Evidence{
			Action:       ch.Action,
			ResourceType: ch.Type,
			ChangePaths:  changePaths,
			Matches:      matches,
		},
	}
}

func decodeAny(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

func findPublicIngress(ch parse.ResourceChange) []string {
	if ch.Type != "aws_security_group" && ch.Type != "aws_security_group_rule" && ch.Type != "aws_vpc_security_group_ingress_rule" {
		return nil
	}

	after := decodeAny(ch.After)
	if after == nil {
		return nil
	}

	rules := extractIngressRules(ch.Type, after)
	var matches []string
	for _, rule := range rules {
		if !rule.publicCIDR {
			continue
		}
		if rule.protocolAll || portOverlapsCommon(rule.fromPort, rule.toPort) {
			matches = append(matches, fmt.Sprintf("%s ports=%d-%d", strings.Join(rule.cidrs, ","), rule.fromPort, rule.toPort))
		}
	}
	sort.Strings(matches)
	return matches
}

type ingressRule struct {
	fromPort    int
	toPort      int
	protocolAll bool
	publicCIDR  bool
	cidrs       []string
}

func extractIngressRules(resourceType string, after any) []ingressRule {
	switch resourceType {
	case "aws_security_group":
		m, ok := after.(map[string]any)
		if !ok {
			return nil
		}
		raw, ok := m["ingress"]
		if !ok {
			return nil
		}
		list, ok := raw.([]any)
		if !ok {
			return nil
		}
		out := make([]ingressRule, 0, len(list))
		for _, item := range list {
			ruleMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, toIngressRule(ruleMap))
		}
		return out

	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		m, ok := after.(map[string]any)
		if !ok {
			return nil
		}
		if t, _ := asString(m["type"]); t != "" && t != "ingress" {
			return nil
		}
		return []ingressRule{toIngressRule(m)}
	default:
		return nil
	}
}

func toIngressRule(m map[string]any) ingressRule {
	cidrs := collectCIDRs(m)
	fromPort, hasFrom := asInt(m["from_port"])
	toPort, hasTo := asInt(m["to_port"])
	if !hasFrom {
		fromPort = 0
	}
	if !hasTo {
		toPort = fromPort
	}
	protocol, _ := asString(m["protocol"])
	protocolAll := protocol == "-1" || strings.EqualFold(protocol, "all")
	return ingressRule{
		fromPort:    fromPort,
		toPort:      toPort,
		protocolAll: protocolAll,
		publicCIDR:  hasPublicCIDR(cidrs),
		cidrs:       cidrs,
	}
}

func collectCIDRs(m map[string]any) []string {
	var out []string
	for _, key := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		list, ok := m[key].([]any)
		if !ok {
			continue
		}
		for _, item := range list {
			if s, ok := asString(item); ok {
				out = append(out, s)
			}
		}
	}
	for _, key := range []string{"cidr_ipv4", "cidr_ipv6"} {
		if s, ok := asString(m[key]); ok && s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func hasPublicCIDR(cidrs []string) bool {
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return true
		}
	}
	return false
}

func portOverlapsCommon(from, to int) bool {
	if from > to {
		from, to = to, from
	}
	for _, p := range publicCommonPorts {
		if p >= from && p <= to {
			return true
		}
	}
	return false
}

func isInternetFacingLB(ch parse.ResourceChange) bool {
	if ch.Type != "aws_lb" && ch.Type != "aws_alb" && ch.Type != "aws_elb" {
		return false
	}
	after, ok := decodeAny(ch.After).(map[string]any)
	if !ok {
		return false
	}

	if scheme, ok := asString(after["scheme"]); ok && scheme == "internet-facing" {
		return true
	}
	if internal, ok := asBool(after["internal"]); ok && !internal {
		return true
	}
	return false
}

func hasPublicIPEnabled(ch parse.ResourceChange) bool {
	after := decodeAny(ch.After)
	if after == nil {
		return false
	}
	if !strings.HasPrefix(ch.Type, "aws_") {
		return false
	}
	keys := []string{"associate_public_ip_address", "map_public_ip_on_launch", "associate_carrier_ip_address"}
	for _, key := range keys {
		if hasTrueField(after, key) {
			return true
		}
	}
	return false
}

func hasTrueField(v any, field string) bool {
	switch typed := v.(type) {
	case map[string]any:
		for k, val := range typed {
			if k == field {
				if b, ok := asBool(val); ok && b {
					return true
				}
			}
			if hasTrueField(val, field) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if hasTrueField(item, field) {
				return true
			}
		}
	}
	return false
}

func isTagOnlyChange(paths []string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, p := range paths {
		base := topLevelPath(p)
		if base != "tags" && base != "tags_all" {
			return false
		}
	}
	return true
}

func topLevelPath(path string) string {
	if idx := strings.Index(path, "."); idx >= 0 {
		path = path[:idx]
	}
	if idx := strings.Index(path, "["); idx >= 0 {
		path = path[:idx]
	}
	return path
}

func isNetworkRoutingType(resourceType string) bool {
	if networkRoutingTypes[resourceType] {
		return true
	}
	for _, prefix := range networkRoutingPrefixes {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

func hasPathHint(paths []string, hints []string) bool {
	return len(filterPaths(paths, hints)) > 0
}

func filterPaths(paths []string, hints []string) []string {
	if len(paths) == 0 || len(hints) == 0 {
		return nil
	}
	var out []string
	for _, p := range paths {
		for _, h := range hints {
			if strings.Contains(p, h) {
				out = append(out, p)
				break
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func dedupeFindings(findings []Finding) []Finding {
	if len(findings) < 2 {
		return findings
	}
	seen := make(map[string]struct{}, len(findings))
	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		key := f.Title + "|" + f.Address + "|" + f.Severity.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asBool(v any) (bool, bool) {
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		parsed, err := strconv.ParseBool(b)
		return parsed, err == nil
	default:
		return false, false
	}
}

func asInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(math.Round(n)), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		parsed, err := n.Int64()
		return int(parsed), err == nil
	case string:
		parsed, err := strconv.Atoi(n)
		return parsed, err == nil
	default:
		return 0, false
	}
}
