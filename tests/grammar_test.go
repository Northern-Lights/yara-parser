package tests

import (
	"log"
	"os"
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
		if rule.Identifier == ruleName && rule.Strings[stringID] != nil {
			return
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
			if rule.Meta != nil {
				var (
					_, s  = rule.Meta["meta_str"]
					_, i  = rule.Meta["meta_int"]
					_, n  = rule.Meta["meta_neg"]
					_, tr = rule.Meta["meta_true"]
					_, f  = rule.Meta["meta_false"]
				)
				if s && i && n && tr && f {
					return
				}
				t.Fatalf(`Ruleset "%s" rule "%s" does not contain all metas`,
					testfile, ruleName)
			}
			t.Fatalf(`Ruleset "%s" rule "%s" has no metadata`,
				testfile, ruleName)
		}
	}

	t.Fatalf(`Ruleset "%s" has no rule "%s"`, testfile, ruleName)
}
