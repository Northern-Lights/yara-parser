package data

// RuleSet represents the contents of a yara file
type RuleSet struct {
	Modules   []string
	Imports   []string
	Includes  []string
	Namespace string
	Rules     []Rule
}

// A Rule is a single yara rule
type Rule struct {
	Modifiers  RuleModifiers
	Identifier string
	Tags       []string
	Meta       Metas
	Strings    map[string]*String
	Condition  string
}

// RuleModifiers denote whether a Rule is global, private, neither, or both.
type RuleModifiers struct {
	Global  bool
	Private bool
}

// Metas is a map which should only be used with values of type
// int, float (64 or 32?), string, bool.
type Metas map[string]interface{}

// String is a string, regex, or byte pair sequence
type String struct {
	ID        string
	Type      StringType
	Text      string
	Modifiers StringModifiers
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
	Nocase   bool
	ASCII    bool
	Wide     bool
	Fullword bool
	I        bool // for regex
	S        bool // for regex
}
