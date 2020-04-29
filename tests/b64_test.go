package tests

import (
	"fmt"
	"testing"

	"github.com/Northern-Lights/yara-parser/data"
)

var b64BadTests = map[string]string{
	"B64_SHORT_ALPHABET":     `"abcdefg" base64(lol)`,
	"B64WIDE_SHORT_ALPHABET": `"abcdefg" base64wide(lol)`,
}

func TestBadB64(t *testing.T) {
	const rsTemplate = `
rule %s {
meta:
	description = "invalid base64 modifier"
strings:
	$s1 = %s
condition:
	$s
}`

	for ruleName, str := range xorBadRangeTests {
		rstr := fmt.Sprintf(rsTemplate, ruleName, str)
		_, err := parseRuleStr(rstr)
		if err == nil {
			t.Errorf(`rule "%s" passed but should have failed`, ruleName)
		}
	}
}

func TestBadB64Serialization(t *testing.T) {
	rules := []data.Rule{
		data.Rule{
			Identifier: "B64_SHORT_ALPHABET",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Base64: data.Base64("lol"),
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "B64WIDE_SHORT_ALPHABET",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Base64: data.Base64("lol"),
					},
				},
			},
			Condition: "$s1",
		},
	}

	for _, rule := range rules {
		s, err := rule.Serialize()
		if err == nil {
			t.Errorf(`%s successfully serialized: %s`, rule.Identifier, s)
		}
	}
}
