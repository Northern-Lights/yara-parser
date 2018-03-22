package data

import (
	"fmt"
	"io"
	"strings"
)

// RuleSet represents the contents of a yara file
type RuleSet struct {
	File     string   `json:"file"` // Name of the yara file
	Imports  []string `json:"imports"`
	Includes []string `json:"includes"`
	Rules    []Rule   `json:"rules"`
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

// Serialize builds the Yara rule
func (rule *Rule) Serialize(output io.Writer) {
	if rule.Modifiers.Global {
		fmt.Fprintf(output, "global ")
	} else if rule.Modifiers.Private {
		fmt.Fprintf(output, "private ")
	}

	fmt.Fprintf(output, "rule %s ", rule.Identifier)
	if len(rule.Tags) > 0 {
		fmt.Fprintf(output, ": %s ", strings.Join(rule.Tags, " "))
	}

	fmt.Fprintf(output, "{ \n")
	if len(rule.Meta) > 0 {
		fmt.Fprintf(output, "  meta:\n")
		for _, meta := range rule.Meta {
			if _, ok := meta.Val.(string); ok {
				fmt.Fprintf(output, "    %s = \"%s\"\n", meta.Key, meta.Val)
			}
			if _, ok := meta.Val.(int64); ok {
				fmt.Fprintf(output, "    %s = %d\n", meta.Key, meta.Val)
			}
			if val, ok := meta.Val.(bool); ok {
				if val {
					fmt.Fprintf(output, "    %s = true\n", meta.Key)
				} else {
					fmt.Fprintf(output, "    %s = false\n", meta.Key)
				}
			}
		}
		fmt.Fprintf(output, "\n")
	}

	if len(rule.Strings) > 0 {
		fmt.Fprintf(output, "  strings:\n")
		for _, s := range rule.Strings {
			if s.Type == TypeString {
				fmt.Fprintf(output, "    %s = \"%s\"", s.ID, s.Text)
			} else if s.Type == TypeRegex {
				fmt.Fprintf(output, "    %s = /%s/", s.ID, s.Text)
			} else if s.Type == TypeHexString {
				fmt.Fprintf(output, "    %s = { %s }", s.ID, s.Text)
			}
			if s.Modifiers.ASCII {
				fmt.Fprintf(output, " ascii")
			}
			if s.Modifiers.Wide {
				fmt.Fprintf(output, " wide")
			}
			if s.Modifiers.Nocase {
				fmt.Fprintf(output, " nocase")
			}
			if s.Modifiers.Fullword {
				fmt.Fprintf(output, " fullword")
			}

			if s.Modifiers.I {
				fmt.Fprintf(output, "i")
			}
			if s.Modifiers.S {
				fmt.Fprintf(output, "s")
			}

			fmt.Fprintf(output, "\n")
		}
		fmt.Fprintf(output, "\n")
	}

	fmt.Fprintf(output, "  condition:\n    %s\n}\n\n", rule.Condition)
}

// RuleModifiers denote whether a Rule is global, private, neither, or both.
type RuleModifiers struct {
	Global  bool `json:"global"`
	Private bool `json:"private"`
}

// Metas are slices of Meta. A single Meta may be duplicated within Metas.
type Metas []Meta

// A Meta is a simple key/value pair. Val should be restricted to
// int, string, and bool.
type Meta struct {
	Key string      `json:"key"`
	Val interface{} `json:"val"`
}

// Strings are slices of String. No two String structs may have the same
// identifier within a Strings, except for the $ anonymous identifier.
type Strings []String

// String is a string, regex, or byte pair sequence
type String struct {
	ID        string          `json:"id"`
	Type      StringType      `json:"type"`
	Text      string          `json:"text"`
	Modifiers StringModifiers `json:"modifiers"`
}

// StringType is used to differentiate between string, hex bytes, and regex
type StringType int

// Type of String
const (
	TypeString StringType = iota
	TypeHexString
	TypeRegex
)

// StringModifiers denote the status of the possible modifiers for strings
type StringModifiers struct {
	Nocase   bool `json:"nocase"`
	ASCII    bool `json:"ascii"`
	Wide     bool `json:"wide"`
	Fullword bool `json:"fullword"`
	I        bool `json:"i"` // for regex
	S        bool `json:"s"` // for regex
}
