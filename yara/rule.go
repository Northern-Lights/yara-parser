package yara

import (
	"fmt"
	"strings"
)

// RuleModifiers denote whether a Rule is global, private, neither, or both.
type RuleModifiers struct {
	Global  bool `json:"global"`
	Private bool `json:"private"`
}

// A Rule is a single yara rule
type Rule struct {
	Modifiers  RuleModifiers `json:"modifiers"`
	Identifier string        `json:"identifier"`
	Tags       []string      `json:"tags"`
	Meta       Metas         `json:"meta"`
	Strings    Strings       `json:"strings"`
	Condition  string        `json:"condition"`
}

// RuleString for Rule builds a YARA rule as a string
func (r *Rule) RuleString() (out string, err error) {
	var b strings.Builder

	// Rule modifiers
	if r.Modifiers.Global {
		b.WriteString("global ")
	}
	if r.Modifiers.Private {
		b.WriteString("private ")
	}

	// Rule name
	b.WriteString(fmt.Sprintf("rule %s ", r.Identifier))

	// Any applicable tags
	if len(r.Tags) > 0 {
		b.WriteString(": ")
		for _, t := range r.Tags {
			b.WriteString(t)
			b.WriteRune(' ')
		}
	}

	// Start metas, strings, etc.
	b.WriteString("{\n")

	metas, err := r.Meta.RuleString()
	if err != nil {
		return
	}
	b.WriteString(metas)

	strs, err := r.Strings.RuleString()
	if err != nil {
		return
	}
	b.WriteString(strs)

	b.WriteString("condition:\n")
	b.WriteString("  ") // TODO: Don't assume indent...
	b.WriteString(r.Condition)
	b.WriteString("\n}\n\n")

	out = b.String()

	return
}
