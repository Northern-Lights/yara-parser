package tests

import (
	"log"
	"os"
	"strings"
	"testing"

	"github.com/Northern-Lights/yara-parser/data"
	"github.com/Northern-Lights/yara-parser/grammar"
)

const testfile = "ruleset.yar"

var ruleset *data.RuleSet

func init() {
	f, err := os.Open(testfile)
	if err != nil {
		log.Fatalf(`Unable to open ruleset file "%s": %s`, testfile, err)
	}
	rs, err := grammar.Parse(f, os.Stderr)
	if err != nil {
		log.Fatalf(`Unable to parse ruleset file "%s": %s`, testfile, err)
	}

	ruleset = &rs
}

// TestRuleNames verifies rule names are being collected
func TestRuleNames(t *testing.T) {

	const ruleName = "BASIC_BOOL"

	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			return
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule named "%s"`, testfile, ruleName)
}

// TestImport verifies imports are being collected
func TestImport(t *testing.T) {

	const i = 1
	if l := len(ruleset.Imports); l < i {
		t.Fatalf("Expected > %d imports in file %s; found %d", i, testfile, l)
	}
}

// TestString verifies that strings are being collected
func TestString(t *testing.T) {

	const (
		ruleName = "STRING1"
		stringID = "$s1"
	)
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			for _, s := range rule.Strings {
				if s.ID == stringID {
					return
				}
			}
			t.Fatalf(`Ruleset "%s" rule "%s" has no string "%s"`,
				testfile, ruleName, stringID)
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule "%s" with string "%s"`,
		testfile, ruleName, stringID)
}

// TestGlobal verifies that the global modifier is being collected
func TestGlobal(t *testing.T) {

	const ruleName = "GLOBAL"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			if rule.Modifiers.Global {
				return
			}
			t.Fatalf(`Ruleset "%s" contains rule "%s" which is not global`,
				testfile, ruleName)
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestPrivate verifies that the private modifier is being collected
func TestPrivate(t *testing.T) {

	const ruleName = "PRIVATE"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			if rule.Modifiers.Private {
				return
			}
			t.Fatalf(`Ruleset "%s" contains rule "%s" which is not private`,
				testfile, ruleName)
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestMeta verifies that metadata is being collected
func TestMeta(t *testing.T) {

	const ruleName = "META"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			checklist := make(map[string]bool)
			for _, kvp := range rule.Meta {
				checklist[kvp.Key] = true
			}

			expecteds := []string{
				"meta_str", "meta_int", "meta_neg", "meta_true", "meta_false",
			}

			for _, expected := range expecteds {
				if !checklist[expected] {
					t.Errorf(`Ruleset "%s" rule "%s" missing expected meta "%s"`,
						testfile, rule.Identifier, expected)
				}
			}
			return
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}

// TestXor verifies that the xor string modifier works
func TestXor(t *testing.T) {
	const ruleName = "XOR"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			for _, s := range rule.Strings {
				const strNamePrefix = "$xor"
				if strings.HasPrefix(s.ID, strNamePrefix) {
					if !s.Modifiers.Xor {
						t.Errorf(`Ruleset "%s" rule "%s" string "%s" xor modifier not found`,
							testfile, rule.Identifier, s.ID)
					}
				} else {
					if s.Modifiers.Xor {
						t.Errorf(`Ruleset "%s" rule "%s" string "%s" has unexpected xor modifier`,
							testfile, rule.Identifier, s.ID)
					}
				}
			}
		}
	}
}

type xorRangeTest struct {
	IsXored bool
	Min     int64
	Max     int64
	Text    string
}

// TestXorRange verifies that the xor string modifier works with bytes range
func TestXorRange(t *testing.T) {
	tests := map[string]xorRangeTest{
		"$xor1":    xorRangeTest{true, 0, 0, `$xor1 = "xor!" xor`},
		"$xor2":    xorRangeTest{true, 0x5d, 0x5d, `$xor2 = "xor?" nocase xor(0x5d)`},
		"$xor3":    xorRangeTest{true, 0xde, 0xff, `$xor3 = /xor_/ xor(0xde-0xff)`},
		"$xor4":    xorRangeTest{true, 127, 0xff, `$xor4 = /xor_/ xor(127-0xff)`},
		"$no_xor1": xorRangeTest{false, 0, 0, `$no_xor1 = "no xor :(" wide`},
		"$no_xor2": xorRangeTest{false, 0, 0, `$no_xor2 = "no xor >:(" ascii nocase`},
	}
	const ruleName = "XOR_RANGE"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			for _, s := range rule.Strings {
				test := tests[s.ID]
				serialized, _ := s.Serialize()
				if s.Modifiers.Xor != test.IsXored ||
					s.Modifiers.XorRange.Min.Val != test.Min ||
					s.Modifiers.XorRange.Max.Val != test.Max ||
					serialized != test.Text {
					t.Errorf(
						`Ruleset "%s" rule "%s" string "%s" ranged xor modifier incorrectly parsed, got - %v, want -%v`,
						testfile, rule.Identifier, s.ID,
						xorRangeTest{s.Modifiers.Xor, s.Modifiers.XorRange.Min.Val, s.Modifiers.XorRange.Max.Val, serialized},
						test,
					)
				}
			}
		}
	}
}
