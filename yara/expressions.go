package yara

import "fmt"

// Boolean is true or false used in a YARA condition
type Boolean bool

func (expr Boolean) RuleString() (out string, err error) {
	if expr == true {
		out = "true"
	} else {
		out = "false"
	}
	return
}

func (expr Boolean) expression() Expression {
	return expr
}

func (expr *Boolean) Set(value bool) {
	*expr = Boolean(value)
}

// StringIdentifier -- e.g. "$s1"
type StringIdentifier struct {
	Identifier string
	at         PrimaryExpression
	in         *Range
}

func (expr StringIdentifier) RuleString() (out string, err error) {
	out = "$" + expr.Identifier
	if expr.at != nil {
		var s string
		s, err = expr.at.RuleString()
		if err != nil {
			return
		}
		out += fmt.Sprintf(` @ %s`, s)
	} else if expr.in != nil {
		var s string
		s, err = expr.in.RuleString()
		if err != nil {
			return
		}
		out += fmt.Sprintf(` in %s`, s)
	}
	return
}

func (expr StringIdentifier) expression() Expression {
	return expr
}

// At -- e.g. "$s1 at 0"
func (expr *StringIdentifier) At(px PrimaryExpression) {
	expr.at = px
	expr.in = nil
}

// In -- e.g. "$s1 in (1..2)"
func (expr *StringIdentifier) In(r *Range) {
	expr.in = r
	expr.at = nil
}

type BinaryExpression struct {
	Left     Expression
	Operator string // TODO: make it a type
	Right    Expression
}

func (expr BinaryExpression) RuleString() (out string, err error) {
	if expr.Left == nil || expr.Right == nil {
		err = fmt.Errorf("yara: nil expression used in %T", expr)
		return
	}

	left, err := expr.Left.RuleString()
	if err != nil {
		return
	}
	right, err := expr.Right.RuleString()
	if err != nil {
		return
	}
	out = fmt.Sprintf("%s %s %s", left, expr.Operator, right)

	return
}

func (expr BinaryExpression) expression() Expression {
	return expr
}

func makeBinaryExpr(expr1, expr2 Expression, operator string) Expression {
	return &BinaryExpression{
		Left:     expr1,
		Operator: operator,
		Right:    expr2,
	}
}

func And(expr1, expr2 Expression) Expression {
	return makeBinaryExpr(expr1, expr2, "and")
}

func Or(expr1, expr2 Expression) Expression {
	return makeBinaryExpr(expr1, expr2, "or")
}

func LT(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, "<")
}

func GT(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, ">")
}

func LE(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, "<=")
}

func GE(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, ">=")
}

func EQ(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, "==")
}

func NEQ(expr1, expr2 PrimaryExpression) Expression {
	return makeBinaryExpr(expr1, expr2, "!=")
}
