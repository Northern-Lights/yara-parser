package data

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
	Nocase   bool     `json:"nocase"`
	ASCII    bool     `json:"ascii"`
	Wide     bool     `json:"wide"`
	Fullword bool     `json:"fullword"`
	Private  bool     `json:"private"`
	Xor      bool     `json:"xor"`
	XorRange XorRange `json:"xor_range"` // makes sense only with XOR modifier
	I        bool     `json:"i"`         // for regex
	S        bool     `json:"s"`         // for regex
}

// XorRange contains upper and lower bounds of the XOR modifier
type XorRange struct {
	Min Int `json:"min"`
	Max Int `json:"max"`
}

// An Int can return its underlying value as int64
type Int interface {
	Value() int64
}

// Dec formats its value using base-10
type Dec int64

// Value --
func (d Dec) Value() int64 {
	return int64(d)
}

// Oct formats its value using base-8
type Oct int64

// Value --
func (o Oct) Value() int64 {
	return int64(o)
}

// Hex formats its value using base-16
type Hex int64

// Value --
func (h Hex) Value() int64 {
	return int64(h)
}
