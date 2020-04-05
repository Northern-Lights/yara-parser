package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Northern-Lights/yara-parser/data"
)

func TestNumberFormat(t *testing.T) {
	const num = 32
	rstr := fmt.Sprintf(`
rule NUM_FORMAT {
meta:
	// description = "test preservation of hex and octal"
	hex = 0x%x
	oct = 0o%o
	dec = %d
condition:
	uint16be(0) == 0x4d5a
}`, num, num, num)

	rs, err := parseRuleStr(rstr)
	if err != nil {
		t.Fatalf(`Parsing failed: %s`, err)
	}

	for _, meta := range rs.Rules[0].Meta {
		switch iface := meta.Val.(type) {
		case data.Hex:
			if meta.Key != "hex" {
				t.Errorf(`expected key "hex" for %T; got %s`, iface, meta.Key)
			}
			if iface.Value() != num {
				t.Errorf(`expected value %d for hex meta; got %d`, num, iface.Value())
			}
			if expect := fmt.Sprintf("0x%x", num); iface.String() != expect {
				t.Errorf(`expected %s; got %s`, expect, iface)
			}
		case data.Oct:
			if meta.Key != "oct" {
				t.Errorf(`expected key "oct" for %T; got %s`, iface, meta.Key)
			}
			if iface.Value() != num {
				t.Errorf(`expected value %d for oct meta; got %d`, num, iface.Value())
			}
			if expect := fmt.Sprintf("0o%o", num); iface.String() != expect {
				t.Errorf(`expected %s; got %s`, expect, iface)
			}
		case data.Dec:
			if meta.Key != "dec" {
				t.Errorf(`expected key "dec" for %T; got %s`, iface, meta.Key)
			}
			if iface.Value() != num {
				t.Errorf(`expected value %d for dec meta; got %d`, num, iface.Value())
			}
			if expect := fmt.Sprintf("%d", num); iface.String() != expect {
				t.Errorf(`expected %s; got %s`, expect, iface)
			}
		}
	}

	const conditionNum = "0x4d5a"
	rsSerialized, err := rs.Serialize()
	if err != nil {
		t.Fatalf(`couldn't serialize ruleset: %s`, err)
	}
	if !strings.Contains(rsSerialized, conditionNum) {
		t.Errorf(`condition: %s (expected %s)`, rsSerialized, conditionNum)
	}
}
