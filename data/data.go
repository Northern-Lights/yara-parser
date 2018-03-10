package data

func init() {
	ResetRuleSet()
}

var rs *RuleSet

// ResetRuleSet resets the global ruleset so the parser can parse a new ruleset
func ResetRuleSet() {
	rs = &RuleSet{}
}

// RuleSet represents the contents of a yara file
type RuleSet struct {
	Modules   []string
	Includes  []string
	Namespace string
	Rules     []Rule
}

// A Rule is a single yara rule
type Rule struct {
	Global     bool
	Private    bool
	Identifier string
	Tags       []string
	Meta       map[string]interface{}
	Strings    map[string]*String
	Condition  string
}

// String is a string, regex, or byte pair sequence
type String struct {
	ID        string
	Type      StringType
	Text      string
	Modifiers []StringModifier
}

// StringType is used to differentiate between string, hex bytes, and regex
type StringType int

// Type of String
const (
	TypeString StringType = iota
	TypeHexString
	TypeRegex
)

// StringModifier is a modifiers to a string identifier
type StringModifier int

// Modifiers related to String type
const (
	StringModNocase StringModifier = iota
	StringModASCII
	StringModWide
	RegexModI
	RegexModS
)
