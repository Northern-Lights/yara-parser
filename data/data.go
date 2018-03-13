package data

// RuleSet represents the contents of a yara file
type RuleSet struct {
	Imports   []string `json:"imports"`
	Includes  []string
	Namespace string
	Rules     []Rule `json:"rules"`
}

// A Rule is a single yara rule
type Rule struct {
	Modifiers  RuleModifiers `json:"modifiers"`
	Identifier string        `json:"identifier"`
	Tags       []string      `json:"tags"`
	Meta       Metas
	Strings    map[string]*String
	Condition  string `json:"condition"`
}

// RuleModifiers denote whether a Rule is global, private, neither, or both.
type RuleModifiers struct {
	Global  bool `json:"global"`
	Private bool `json:"private"`
}

// Metas is a map which should only be used with values of type
// int, string, bool.
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
