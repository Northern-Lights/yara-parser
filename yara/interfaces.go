package yara

// A RuleStringer can be serialized into text used in YARA rules
type RuleStringer interface {
	RuleString() string
}
