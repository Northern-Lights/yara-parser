package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/Northern-Lights/yara-parser/grammar"
)

const (
	dupmeta = "duplicate-meta.yar"
	dupstr  = "duplicate-strings.yar"
)

func TestDuplicateMeta(t *testing.T) {
	f, err := os.Open(dupmeta)
	if err != nil {
		t.Fatalf(`Couldn't open meta ruleset "%s": %s`, dupmeta, err)
	}

	ruleset, err := grammar.Parse(f, os.Stderr)
	if err != nil {
		t.Fatalf(`Parsing ruleset "%s" failed: %s`, dupmeta, err)
	}

	const nrules = 1
	if l := len(ruleset.Rules); l != nrules {
		t.Fatalf(`Ruleset "%s" has %d rules; expected %d`, dupmeta, l, nrules)
	}

	var (
		rule  = ruleset.Rules[0]
		key   = "description"
		vals  = rule.Meta[key]
		nvals = len(vals)
	)
	const expectedVals = 3

	if nvals != expectedVals {
		t.Fatalf(`Rule "%s" in ruleset "%s" has %d metas for key "%s"; expected %d`,
			rule.Identifier, dupmeta, nvals, key, expectedVals)
	}
}

func TestDuplicateStrings(t *testing.T) {
	f, err := os.Open(dupstr)
	if err != nil {
		t.Fatalf(`Couldn't open str ruleset "%s": %s`, dupstr, err)
	}

	_, err = grammar.Parse(f, os.Stderr)
	if err == nil {
		t.Fatalf(`Parsing ruleset "%s" should have failed with duplicate strings`, dupstr)
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf(`Parsing ruleset "%s" yielded non-duplicate string error: %s`, dupstr, err)
	}
}
