package yara

import "fmt"

type PrimaryExpressionKeyword string

func (px PrimaryExpressionKeyword) RuleString() (string, error) {
	// TODO: filter invalid ones
	return string(px), nil
}

func (px PrimaryExpressionKeyword) expression() Expression {
	return px
}

func (px PrimaryExpressionKeyword) primaryExpression() PrimaryExpression {
	return px
}

const (
	Filesize   PrimaryExpressionKeyword = "filesize"
	Entrypoint PrimaryExpressionKeyword = "entrypoint"
)

type IntegerFunction struct {
	Name IntegerFunctionName
	Arg  PrimaryExpression
}

type IntegerFunctionName string

const (
	Int8     IntegerFunctionName = "int8"
	Int16    IntegerFunctionName = "int16"
	Int32    IntegerFunctionName = "int32"
	Uint8    IntegerFunctionName = "uint8"
	Uint16   IntegerFunctionName = "uint16"
	Uint32   IntegerFunctionName = "uint32"
	Int8be   IntegerFunctionName = "int8be"
	Int16be  IntegerFunctionName = "int16be"
	Int32be  IntegerFunctionName = "int32be"
	Uint8be  IntegerFunctionName = "uint8be"
	Uint16be IntegerFunctionName = "uint16be"
	Uint32be IntegerFunctionName = "uint32be"
)

func (px IntegerFunction) RuleString() (out string, err error) {
	arg, err := px.Arg.RuleString()
	if err != nil {
		return
	}
	out = fmt.Sprintf("%s(%s)", px.Name, arg)
	return
}

func (px IntegerFunction) expression() Expression {
	return px
}

func (px IntegerFunction) primaryExpression() PrimaryExpression {
	return px
}

// Number -- base info is lost during parsing, so it will only be represented as
// base-10 when serializing back into YARA Rule text
type Number int64

func (px Number) RuleString() (out string, err error) {
	return fmt.Sprintf("%d", px), nil
}

func (px Number) expression() Expression {
	return px
}

func (px Number) primaryExpression() PrimaryExpression {
	return px
}

// Double -- same situation as Number but for float64
type Double float64

// RuleString outputs a float64 as a string
func (px Double) RuleString() (out string, err error) {
	return fmt.Sprintf("%f", px), nil
}

func (px Double) expression() Expression {
	return px
}

func (px Double) primaryExpression() PrimaryExpression {
	return px
}

type TextString string

func (px TextString) RuleString() (out string, err error) {
	return string(px), nil
}

func (px TextString) expression() Expression {
	return px
}

func (px TextString) primaryExpression() PrimaryExpression {
	return px
}

// StringCount -- #s1
type StringCount string

func (px StringCount) RuleString() (out string, err error) {
	const operator = '#'
	if len(px) < 2 {
		err = fmt.Errorf("invalid length %d for %T", len(px), px)
		return
	} else if px[0] != operator {
		err = fmt.Errorf("%T must begin with %c", px, operator)
		return
	}
	// TODO: validate identifier

	out = string(px)
	return
}

func (px StringCount) primaryExpression() PrimaryExpression {
	return px
}

func (px StringCount) expression() Expression {
	return px
}

// StringOffset -- @s1 or @s1[PrimaryExpression]
type StringOffset struct {
	Identifier string
	Occurrence PrimaryExpression
}

func (px StringOffset) RuleString() (out string, err error) {
	const operator = '@'
	if len(px.Identifier) < 2 {
		err = fmt.Errorf("invalid length %d for %T", len(px.Identifier), px)
		return
	} else if px.Identifier[0] != operator {
		err = fmt.Errorf("%T must begin with %c", px, operator)
		return
	}
	// TODO: validate identifier

	out = px.Identifier
	if px.Occurrence != nil {
		var offset string
		offset, err = px.Occurrence.RuleString()
		if err != nil {
			return
		}
		out = fmt.Sprintf("%s[%s]", out, offset)
	}

	return
}

func (px StringOffset) primaryExpression() PrimaryExpression {
	return px
}

func (px StringOffset) expression() Expression {
	return px
}

// StringLength -- !s1 or !s1[PrimaryExpression]
type StringLength struct {
	Identifier string
	Occurrence PrimaryExpression
}

func (px StringLength) RuleString() (out string, err error) {
	const operator = '!'
	if len(px.Identifier) < 2 {
		err = fmt.Errorf("invalid length %d for %T", len(px.Identifier), px)
		return
	} else if px.Identifier[0] != operator {
		err = fmt.Errorf("%T must begin with %c", px, operator)
		return
	}
	// TODO: validate identifier

	out = px.Identifier
	if px.Occurrence != nil {
		var offset string
		offset, err = px.Occurrence.RuleString()
		if err != nil {
			return
		}
		out = fmt.Sprintf("%s[%s]", out, offset)
	}

	return
}

func (px StringLength) primaryExpression() PrimaryExpression {
	return px
}

func (px StringLength) expression() Expression {
	return px
}

// BinaryPrimaryExpression -- e.g. "1 & PrimaryExpression" or "!s1 % 16"
type BinaryPrimaryExpression struct {
	Left     PrimaryExpression
	Operator string // TODO: make it a type
	Right    PrimaryExpression
}

func (px BinaryPrimaryExpression) RuleString() (out string, err error) {
	var (
		left  string
		right string
	)

	left, err = px.Left.RuleString()
	if err != nil {
		return
	}
	right, err = px.Right.RuleString()
	if err != nil {
		return
	}

	// TODO: () around primary expressions?
	// TODO: verify operator
	out = fmt.Sprintf("%s %s %s", left, px.Operator, right)
	return
}
