package tests

import (
	"fmt"
	"testing"

	"github.com/Northern-Lights/yara-parser/yara"
)

func TestExpr(t *testing.T) {
	var rule yara.Rule
	rule.Identifier = "rulename"
	rule.Strings = yara.Strings{
		yara.String{
			ID:   "$s1",
			Type: yara.TypeString,
			Text: "abcdefg",
		},
	}

	var e1 yara.Boolean
	e1.Set(true)
	e2 := yara.StringIdentifier{
		Identifier: "s1",
	}
	rule.Condition = yara.And(e1, e2)

	rs := yara.RuleSet{
		Imports: []string{"pe"},
		Rules: []yara.Rule{
			rule,
		},
	}

	str, err := rs.RuleString()
	if err != nil {
		t.Fatal("Couldn't serialize rule:", err)
	}
	fmt.Println(str)
}
