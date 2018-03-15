package data

// RuleSet represents the contents of a yara file
type RuleSet struct {
	Imports  []string `json:"imports"`
	Includes []string `json:"includes"`
	Rules    []Rule   `json:"rules"`
}

// A Rule is a single yara rule
type Rule struct {
	Modifiers  RuleModifiers      `json:"modifiers"`
	Identifier string             `json:"identifier"`
	Tags       []string           `json:"tags"`
	Meta       Metas              `json:"meta"`
	Strings    map[string]*String `json:"strings"`
	Condition  string             `json:"condition"`
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
