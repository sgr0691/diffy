package parse

import (
	"testing"
)

func TestDeriveActionCreate(t *testing.T) {
	changes, err := parseJSON([]byte(`{
		"resource_changes": [{
			"address": "aws_instance.test",
			"type": "aws_instance",
			"change": {"actions": ["create"], "before": null, "after": {}}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Action != ActionCreate {
		t.Errorf("expected create, got %s", changes[0].Action)
	}
}

func TestDeriveActionReplace(t *testing.T) {
	changes, err := parseJSON([]byte(`{
		"resource_changes": [{
			"address": "aws_instance.test",
			"type": "aws_instance",
			"change": {"actions": ["delete","create"], "before": {}, "after": {}}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Action != ActionReplace {
		t.Errorf("expected replace, got %s", changes[0].Action)
	}
}

func TestDeriveActionDelete(t *testing.T) {
	changes, err := parseJSON([]byte(`{
		"resource_changes": [{
			"address": "aws_instance.test",
			"type": "aws_instance",
			"change": {"actions": ["delete"], "before": {}, "after": null}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].Action != ActionDelete {
		t.Errorf("expected delete, got %s", changes[0].Action)
	}
}

func TestNoopIsSkipped(t *testing.T) {
	changes, err := parseJSON([]byte(`{
		"resource_changes": [{
			"address": "aws_instance.test",
			"type": "aws_instance",
			"change": {"actions": ["no-op"], "before": {}, "after": {}}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 0 {
		t.Errorf("expected 0 changes (no-op skipped), got %d", len(changes))
	}
}

func TestComputeCounts(t *testing.T) {
	changes := []ResourceChange{
		{Action: ActionCreate},
		{Action: ActionCreate},
		{Action: ActionUpdate},
		{Action: ActionDelete},
		{Action: ActionReplace},
	}
	c := ComputeCounts(changes)
	if c.Create != 2 {
		t.Errorf("expected 2 creates, got %d", c.Create)
	}
	if c.Update != 1 {
		t.Errorf("expected 1 update, got %d", c.Update)
	}
	if c.Delete != 1 {
		t.Errorf("expected 1 delete, got %d", c.Delete)
	}
	if c.Replace != 1 {
		t.Errorf("expected 1 replace, got %d", c.Replace)
	}
	if c.Total != 5 {
		t.Errorf("expected 5 total, got %d", c.Total)
	}
}

func TestFromFile(t *testing.T) {
	changes, err := FromFile("../../examples/plan/replace.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(changes))
	}
	if changes[0].Action != ActionReplace {
		t.Errorf("expected first change to be replace, got %s", changes[0].Action)
	}
	if changes[1].Action != ActionUpdate {
		t.Errorf("expected second change to be update, got %s", changes[1].Action)
	}
}
