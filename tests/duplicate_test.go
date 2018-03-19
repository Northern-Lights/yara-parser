package tests

import (
	"os"
	"strings"
	"testing"

	"github.com/Northern-Lights/yara-parser/grammar"
)

const (
	dupmeta    = "duplicate-meta.yar"
	dupstr     = "duplicate-strings.yar"
	dupstranon = "duplicate-strings-anon.yar"
	duptag     = "duplicate-tags.yar"
	duprule    = "duplicate-rules.yar"
)

func TestDuplicateRules(t *testing.T) {
	f, err := os.Open(duprule)
	if err != nil {
		t.Fatalf(`Couldn't open dup rules ruleset "%s": %s`, duprule, err)
	}

	_, err = grammar.Parse(f, os.Stderr)
	if err == nil {
		t.Fatalf(`Parsing ruleset "%s" should have failed with duplicate rules`,
			duprule)
	} else if !strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Fatalf(`Parsing ruleset "%s" failed with error other than duplicate rules: %s`,
			duprule, err)
	}
}

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
		nvals = len(rule.Meta)
	)
	const expectedVals = 4

	if nvals != expectedVals {
		t.Fatalf(`Rule "%s" in ruleset "%s" has %d metas for key "%s"; expected %d`,
			rule.Identifier, dupmeta, nvals, key, expectedVals)
	}

	for _, meta := range rule.Meta {
		if meta.Key != key {
			t.Errorf(`Expecting all keys to be "%s"; found "%s"`, key, meta.Key)
		}
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

func TestDuplicateStringsAnonymous(t *testing.T) {
	f, err := os.Open(dupstranon)
	if err != nil {
		t.Fatalf(`Couldn't open str anon ruleset "%s": %s`, dupstranon, err)
	}

	_, err = grammar.Parse(f, os.Stderr)
	if err != nil {
		t.Fatalf(`Parsing ruleset "%s" failed: %s`, dupstranon, err)
	}
}

func TestDuplicateTags(t *testing.T) {
	f, err := os.Open(duptag)
	if err != nil {
		t.Fatalf(`Couldn't open dup tag ruleset "%s": %s`, duptag, err)
	}

	_, err = grammar.Parse(f, os.Stderr)
	if err == nil {
		t.Fatalf(`Parsing ruleset "%s" should have failed with duplicate tags`, duptag)
	} else if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf(`Parsing ruleset "%s" yielded non-duplicate tag error: %s`, duptag, err)
	}
}
