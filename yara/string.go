package yara

import (
	"fmt"
	"strings"
)

// Strings are slices of String. No two String structs may have the same
// identifier within a Strings, except for the $ anonymous identifier.
type Strings []String

// RuleString for Strings returns the "strings:" section in the YARA rule
func (ss *Strings) RuleString() (out string, err error) {
	if ss == nil || len(*ss) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("strings:\n")

	for _, s := range *ss {
		str, e := s.RuleString()
		if e != nil {
			err = e
			return
		}
		b.WriteString("  ") // TODO: Make indent customizable
		b.WriteString(str)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// String is a string, regex, or byte pair sequence
type String struct {
	ID        string          `json:"id"`
	Type      StringType      `json:"type"`
	Text      string          `json:"text"`
	Modifiers StringModifiers `json:"modifiers"`
}

// RuleString for String returns a String as a string
func (s *String) RuleString() (out string, err error) {
	// Format string for:
	// `<identifier> = <encapsOpen> <text> <encapsClose> <modifiers>`
	format := "%s = %s%s%s %s"

	var (
		encapsOpen  string
		encapsClose string
	)
	switch t := s.Type; t {
	case TypeString:
		encapsOpen, encapsClose = `"`, `"`

	case TypeHexString:
		encapsOpen, encapsClose = "{", "}"

	case TypeRegex:
		encapsOpen = "/"
		encapsClose = "/"
		if s.Modifiers.I {
			encapsClose += "i"
		}
		if s.Modifiers.S {
			encapsClose += "s"
		}

	default:
		err = fmt.Errorf("No such string type %d", t)
		return
	}

	mods, _ := s.Modifiers.RuleString()

	out = fmt.Sprintf(format, s.ID, encapsOpen, s.Text, encapsClose, mods)

	return
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
	Xor      bool `json:"xor"`
	I        bool `json:"i"` // for regex
	S        bool `json:"s"` // for regex
}

// RuleString for StringModifiers creates a space-sparated list of
// string modifiers, excluding the i and s which are appended to /regex/
// The returned error must be nil.
func (m *StringModifiers) RuleString() (out string, _ error) {
	const modsAvailable = 4
	modifiers := make([]string, 0, modsAvailable)
	if m.ASCII {
		modifiers = append(modifiers, "ascii")
	}
	if m.Wide {
		modifiers = append(modifiers, "wide")
	}
	if m.Nocase {
		modifiers = append(modifiers, "nocase")
	}
	if m.Fullword {
		modifiers = append(modifiers, "fullword")
	}
	if m.Xor {
		modifiers = append(modifiers, "xor")
	}

	out = strings.Join(modifiers, " ")
	return
}
