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
	Condition  Expression    `json:"condition"`
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
	Nocase   bool `json:"nocase"`
	ASCII    bool `json:"ascii"`
	Wide     bool `json:"wide"`
	Fullword bool `json:"fullword"`
	I        bool `json:"i"` // for regex
	S        bool `json:"s"` // for regex
}

type Keyword string

var (
	KeywordAll        Keyword = "all"
	KeywordAny        Keyword = "any"
	KeywordEntrypoint Keyword = "entrypoint"
	KeywordFilesize   Keyword = "filesize"
	KeywordThem       Keyword = "them"
)

type Operator string

var (
	OperatorIntegerFunction Operator = "integer_function" // TODO: document custom operator
	OperatorUnaryMinus      Operator = "unary-minus"
	OperatorPlus            Operator = "+"
	OperatorMinus           Operator = "-"
	OperatorTimes           Operator = "*"
	OperatorDivide          Operator = "\\"
	OperatorModulo          Operator = "%"
	OperatorXor             Operator = "^"
	OperatorBitwiseAnd      Operator = "&"
	OperatorBitwiseOr       Operator = "|"
	OperatorBitwiseNot      Operator = "~"
	OperatorShiftLeft       Operator = "<<"
	OperatorShiftRight      Operator = ">>"
)

type Expression struct {
	Left interface{}
	Operator
	Right interface{}
}

// #Identifier
type StringCount struct {
	Identifier string
}

// $Base[Index]
type StringOffset struct {
	Base  string
	Index interface{}
}

// !Base[Index]
type StringLength struct {
	Base  string
	Index interface{}
}

// One of Expression, Keyword{Name: "all"} or Keyword{Name: "any"}
type ForExpression struct {
	Expression
	Keyword
}

type ForInExpression struct {
	ForExpression
	Identifier string
	IntegerSet
	Boolean Expression
}

type ForOfExpression struct {
	ForExpression
	StringSet
	Boolean Expression
}

// One of Range or IntArray
type IntegerSet struct {
	Range
	IntArray []int64
}

// One of Array or KeywordThem
type StringSet struct {
	Array []string
	Keyword
}

type Range struct {
	From Expression
	To   Expression
}

// Used during parsing, eventually gets elided?
type TemporaryString struct {
	Identifier string
}
