package parse

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
)

// tfPlan is the subset of Terraform's JSON plan format we care about.
type tfPlan struct {
	ResourceChanges []tfResourceChange `json:"resource_changes"`
}

type tfResourceChange struct {
	Address      string   `json:"address"`
	Type         string   `json:"type"`
	ProviderName string   `json:"provider_name"`
	Change       tfChange `json:"change"`
}

type tfChange struct {
	Actions json.RawMessage `json:"actions"`
	Before  json.RawMessage `json:"before"`
	After   json.RawMessage `json:"after"`
}

// FromFile reads and parses a Terraform plan JSON file.
func FromFile(path string) ([]ResourceChange, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading plan file: %w", err)
	}
	return parseJSON(data)
}

// FromPlanBinary runs `terraform show -json <path>` and parses the output.
func FromPlanBinary(path string) ([]ResourceChange, error) {
	tfPath, err := exec.LookPath("terraform")
	if err != nil {
		return nil, fmt.Errorf("terraform not found in PATH — install it from https://developer.hashicorp.com/terraform/install and try again")
	}

	cmd := exec.Command(tfPath, "show", "-json", path)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("terraform show failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("running terraform show: %w", err)
	}
	return parseJSON(out)
}

func parseJSON(data []byte) ([]ResourceChange, error) {
	var plan tfPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parsing plan JSON: %w", err)
	}

	changes := make([]ResourceChange, 0, len(plan.ResourceChanges))
	for _, rc := range plan.ResourceChanges {
		action := deriveAction(rc.Change.Actions)
		if action == ActionNoop {
			continue
		}
		changes = append(changes, ResourceChange{
			Address:      rc.Address,
			Type:         rc.Type,
			ProviderName: rc.ProviderName,
			Action:       action,
			Before:       rc.Change.Before,
			After:        rc.Change.After,
			ChangePaths:  computeChangePaths(rc.Change.Before, rc.Change.After),
		})
	}
	return changes, nil
}

func deriveAction(raw json.RawMessage) Action {
	var actions []string
	if err := json.Unmarshal(raw, &actions); err != nil {
		return ActionNoop
	}
	if len(actions) == 0 {
		return ActionNoop
	}

	// Terraform encodes replace as ["delete","create"]
	if len(actions) == 2 && actions[0] == "delete" && actions[1] == "create" {
		return ActionReplace
	}
	// Also handle ["create","delete"] just in case
	if len(actions) == 2 && actions[0] == "create" && actions[1] == "delete" {
		return ActionReplace
	}

	switch actions[0] {
	case "create":
		return ActionCreate
	case "update":
		return ActionUpdate
	case "delete":
		return ActionDelete
	case "no-op", "read":
		return ActionNoop
	default:
		return ActionNoop
	}
}

// ComputeCounts tallies changes by action.
func ComputeCounts(changes []ResourceChange) Counts {
	var c Counts
	for _, ch := range changes {
		switch ch.Action {
		case ActionCreate:
			c.Create++
		case ActionUpdate:
			c.Update++
		case ActionDelete:
			c.Delete++
		case ActionReplace:
			c.Replace++
		}
	}
	c.Total = c.Create + c.Update + c.Delete + c.Replace
	return c
}

func computeChangePaths(beforeRaw, afterRaw json.RawMessage) []string {
	var before any
	var after any
	if len(beforeRaw) > 0 {
		_ = json.Unmarshal(beforeRaw, &before)
	}
	if len(afterRaw) > 0 {
		_ = json.Unmarshal(afterRaw, &after)
	}

	var out []string
	diffAny("", before, after, &out)
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	deduped := out[:0]
	for i, p := range out {
		if i == 0 || out[i-1] != p {
			deduped = append(deduped, p)
		}
	}
	return deduped
}

func diffAny(path string, before, after any, out *[]string) {
	if reflect.DeepEqual(before, after) {
		return
	}

	beforeMap, beforeIsMap := before.(map[string]any)
	afterMap, afterIsMap := after.(map[string]any)
	if beforeIsMap && afterIsMap {
		keys := make(map[string]struct{}, len(beforeMap)+len(afterMap))
		for k := range beforeMap {
			keys[k] = struct{}{}
		}
		for k := range afterMap {
			keys[k] = struct{}{}
		}

		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		sort.Strings(ordered)

		for _, k := range ordered {
			child := k
			if path != "" {
				child = path + "." + k
			}
			bv, bok := beforeMap[k]
			av, aok := afterMap[k]
			if !bok || !aok {
				*out = append(*out, child)
				continue
			}
			diffAny(child, bv, av, out)
		}
		return
	}

	beforeList, beforeIsList := before.([]any)
	afterList, afterIsList := after.([]any)
	if beforeIsList && afterIsList {
		if len(beforeList) != len(afterList) {
			if path != "" {
				*out = append(*out, path)
			}
			return
		}
		for i := range beforeList {
			child := path + "[" + strconv.Itoa(i) + "]"
			diffAny(child, beforeList[i], afterList[i], out)
		}
		return
	}

	if path != "" {
		*out = append(*out, path)
	}
}
