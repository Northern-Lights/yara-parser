package yara

// A RuleStringer can be serialized into text used in YARA rules
type RuleStringer interface {
	RuleString() (string, error)
}

// Expression -- see gramamr.y
type Expression interface {
	RuleStringer
	expression() Expression
	// Children() []Expression
}

type PrimaryExpression interface {
	Expression
	primaryExpression() PrimaryExpression
}
