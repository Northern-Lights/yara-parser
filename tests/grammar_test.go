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
					if s.Modifiers.Xor == nil {
						t.Errorf(`Ruleset "%s" rule "%s" string "%s" xor modifier not found`,
							testfile, rule.Identifier, s.ID)
					}
				} else {
					if s.Modifiers.Xor != nil {
						t.Errorf(`Ruleset "%s" rule "%s" string "%s" has unexpected xor modifier`,
							testfile, rule.Identifier, s.ID)
					}
				}
			}
		}
	}
}

type xorRangeTest struct {
	Xor  data.Xor
	Text string
}

// TestXorRange verifies that the xor string modifier works with bytes range
func TestXorRange(t *testing.T) {
	tests := map[string]xorRangeTest{
		"$xor1": xorRangeTest{
			Xor:  data.Xor{data.Dec(0)},
			Text: `$xor1 = "xor!" xor(0)`,
		},
		"$xor2": xorRangeTest{
			Xor:  data.Xor{data.Hex(0x5d)},
			Text: `$xor2 = "xor?" ascii xor(0x5d)`,
		},
		"$xor3": xorRangeTest{
			Xor:  data.Xor{data.Hex(0xde), data.Hex(0xff)},
			Text: `$xor3 = "^xor_$!" xor(0xde-0xff)`,
		},
		"$xor4": xorRangeTest{
			Xor:  data.Xor{data.Dec(132), data.Hex(0xff)},
			Text: `$xor4 = "xor?" private xor(132-0xff)`,
		},
		"$no_xor1": xorRangeTest{
			Xor:  nil,
			Text: `$no_xor1 = "no xor :(" wide`,
		},
		"$no_xor2": xorRangeTest{
			Xor:  nil,
			Text: `$no_xor2 = "no xor >:(" ascii nocase`,
		},
		"$no_xor3": xorRangeTest{
			Xor:  nil,
			Text: `$no_xor3 = /xor_/ ascii`,
		},
	}
	const ruleName = "XOR_RANGE"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			for _, s := range rule.Strings {
				test := tests[s.ID]
				serialized, _ := s.Serialize()
				if serialized != test.Text {
					t.Errorf(`Ruleset "%s" rule "%s" got strings "%s"; expected "%s"`,
						testfile, rule.Identifier, serialized, test.Text)
				}
				bothNil := s.Modifiers.Xor == nil && test.Xor == nil
				bothPresent := s.Modifiers.Xor != nil && test.Xor != nil
				if !(bothNil || bothPresent) {
					t.Errorf(`Ruleset "%s" rule "%s" xor = %v; want %v`,
						testfile, rule.Identifier, s.Modifiers.Xor, test.Xor)
				} else if len(s.Modifiers.Xor) != len(test.Xor) {
					t.Errorf(`Ruleset "%s" rule "%s" xor = %v; expected %v`,
						testfile, rule.Identifier, s.Modifiers.Xor, test.Xor)
				} else {
					for i := range test.Xor {
						if test.Xor[i] != s.Modifiers.Xor[i] {
							t.Errorf(`Ruleset "%s" rule "%s" xor arg %d = %s (%T); expected %s (%T)`,
								testfile, rule.Identifier, i,
								s.Modifiers.Xor[i], s.Modifiers.Xor[i], test.Xor[i], test.Xor[i])
						}
					}
				}
			}
		}
	}
}

type privateStrTest struct {
	IsPrivate bool
	Text      string
}

// TestPrivateString verifies that the private string modifier works
func TestPrivateString(t *testing.T) {
	tests := map[string]privateStrTest{
		"$private1":    privateStrTest{true, `$private1 = "private!" private`},
		"$private2":    privateStrTest{true, `$private2 = "private?" wide private`},
		"$private3":    privateStrTest{true, `$private3 = /private_/ wide nocase private`},
		"$no_private1": privateStrTest{false, `$no_private1 = "no private :(" wide xor`},
		"$no_private2": privateStrTest{false, `$no_private2 = "no private >:(" ascii nocase`},
	}
	const ruleName = "PRIVATE_STRING"
	for _, rule := range ruleset.Rules {
		if rule.Identifier == ruleName {
			for _, s := range rule.Strings {
				test := tests[s.ID]
				serialized, _ := s.Serialize()
				if s.Modifiers.Private != test.IsPrivate || serialized != test.Text {
					t.Errorf(
						`Ruleset "%s" rule "%s" string "%s" ranged private modifier incorrectly parsed, got - %v, want -%v`,
						testfile, rule.Identifier, s.ID, privateStrTest{s.Modifiers.Private, serialized}, test,
					)
				}
			}
		}
	}
}

func TestB64(t *testing.T) {
	ruleName := "BASE64_NO_ALPHABET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	s := rule.Strings[0]
	if s.Modifiers.Base64 == nil {
		t.Fatalf(`nil base64 modifier for %s`, ruleName)
	}
	if len(s.Modifiers.Base64) != 0 {
		t.Errorf(`Expected no alphabet; got alphabet of size %d`, len(s.Modifiers.Base64))
	}
}

func TestB64Alphabet(t *testing.T) {
	ruleName := "BASE64_ALPHABET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	s := rule.Strings[0]
	if s.Modifiers.Base64 == nil {
		t.Fatalf(`nil base64 modifier for %s`, ruleName)
	}
	if len(s.Modifiers.Base64) != 64 {
		t.Errorf(`Expected alphabet of size 64; got size %d`, len(s.Modifiers.Base64))
	}
}

func TestB64Wide(t *testing.T) {
	ruleName := "BASE64WIDE_NO_ALPHABET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	s := rule.Strings[0]
	if s.Modifiers.Base64Wide == nil {
		t.Fatalf(`nil base64 modifier for %s`, ruleName)
	}
	if len(s.Modifiers.Base64Wide) != 0 {
		t.Errorf(`Expected no alphabet; got alphabet of size %d`, len(s.Modifiers.Base64Wide))
	}
}

func TestB64WideAlphabet(t *testing.T) {
	ruleName := "BASE64WIDE_ALPHABET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	s := rule.Strings[0]
	if s.Modifiers.Base64Wide == nil {
		t.Fatalf(`nil base64 modifier for %s`, ruleName)
	}
	if len(s.Modifiers.Base64Wide) != 64 {
		t.Errorf(`Expected alphabet of size 64; got size %d`, len(s.Modifiers.Base64Wide))
	}
}

func getRule(name string) data.Rule {
	for _, rule := range ruleset.Rules {
		if rule.Identifier == name {
			return rule
		}
	}
	return data.Rule{}
}

func TestStringsSetInRange(t *testing.T) {
	ruleName := "STRINGS_SET_IN_RANGE"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	if len(rule.Condition) == 0 {
		t.Errorf(`Condition parsing has failed`)
	}
}

func TestAnyOfRulesSet(t *testing.T) {
	ruleName := "ANY_OF_RULES_SET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Condition) == 0 {
		t.Errorf(`Condition parsing has failed`)
	}
}

func TestAnyOfStringsSet(t *testing.T) {
	ruleName := "ANY_OF_STRINGS_SET"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 4 {
		t.Fatalf(`Expected 4 string; got %d`, len(rule.Strings))
	}
	if len(rule.Condition) == 0 {
		t.Errorf(`Condition parsing has failed`)
	}
}

func TestInDotDotRange(t *testing.T) {
	ruleName := "IN_DOTDOT_RANGE"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 1 {
		t.Fatalf(`Expected 1 string; got %d`, len(rule.Strings))
	}
	if len(rule.Condition) == 0 {
		t.Errorf(`Condition parsing has failed`)
	}
}

func TestAnyInDotDotRange(t *testing.T) {
	ruleName := "ANY_IN_DOTDOT_RANGE"
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Fatalf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Strings) != 2 {
		t.Fatalf(`Expected 2 string; got %d`, len(rule.Strings))
	}
	if len(rule.Condition) == 0 {
		t.Errorf(`Condition parsing has failed`)
	}
}

func TestDefinedNotDefined(t *testing.T) {
	verifyConditionParses(t, "DEFINED_NOT_DEFINED")
}

func TestStartsWith(t *testing.T) {
	verifyConditionParses(t, "STARTS_WITH")
}

func TestEndsWith(t *testing.T) {
	verifyConditionParses(t, "ENDS_WITH")
}

func TestIContains(t *testing.T) {
	verifyConditionParses(t, "ICONTAINS")
}

func TestIStartsWith(t *testing.T) {
	verifyConditionParses(t, "ISTARTS_WITH")
}

func TestIEndsWith(t *testing.T) {
	verifyConditionParses(t, "IENDS_WITH")
}

func TestIEquals(t *testing.T) {
	verifyConditionParses(t, "IEQUALS")
}

func TestNone(t *testing.T) {
	verifyConditionParses(t, "NONE")
}

func verifyConditionParses(t *testing.T, ruleName string) {
	t.Helper()
	rule := getRule(ruleName)
	if rule.Identifier == "" {
		t.Errorf(`rule "%s" not found`, ruleName)
	}
	if len(rule.Condition) == 0 {
		t.Error("failed to parse condition")
	}
}
