package tests

import (
	"fmt"
	"testing"

	"github.com/Northern-Lights/yara-parser/data"
)

var xorBadRangeTests = map[string]string{
	"XOR_NEGATIVE_ARG":   `"abcdefg" xor(-1)`,
	"XOR_REVERSED_RANGE": `"abcdefg" xor(123-1)`,
	"XOR_OUT_OF_RANGE1":  `"abcdefg" xor(0x100)`,
	"XOR_OUT_OF_RANGE2":  `"abcdefg" xor(0x10-0x101)`,
	"XOR_WITH_REGEX":     `/abcdefg/ xor`,
	"XOR_WITH_HEXPAIRS":  `{ab cd ef} xor`,
}

func TestBadXor(t *testing.T) {
	const rsTemplate = `
rule %s {
meta:
	description = "invalid negative argument to xor modifier"
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
		// xor in regex and some others cause errors in lexical scanning, not
		// modifier identification, therefore we cannot identify use of xor as
		// invalid modifier
		/* else if !errors.Is(err, data.ErrInvalidStringModifierCombo) {
			t.Errorf(`rule %s failed with "%s"; should have failed with "%s"`,
				ruleName, err, data.ErrInvalidStringModifierCombo)
		}*/
	}
}

func TestBadXorSerialization(t *testing.T) {
	rules := []data.Rule{
		data.Rule{
			Identifier: "XOR_NEGATIVE_ARG",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{data.Dec(-1)},
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "XOR_REVERSED_RANGE",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{data.Dec(123), data.Dec(1)},
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "XOR_OUT_OF_RANGE1",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{data.Hex(0x100)},
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "XOR_OUT_OF_RANGE2",
			Strings: data.Strings{
				data.String{
					Type: data.TypeString,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{data.Hex(0x10), data.Hex(0x101)},
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "XOR_WITH_REGEX",
			Strings: data.Strings{
				data.String{
					Type: data.TypeRegex,
					ID:   "$s1",
					Text: "abcdefg",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{},
					},
				},
			},
			Condition: "$s1",
		},

		data.Rule{
			Identifier: "XOR_WITH_HEXPAIRS",
			Strings: data.Strings{
				data.String{
					Type: data.TypeHexString,
					ID:   "$s1",
					Text: "ab cd ef",
					Modifiers: data.StringModifiers{
						Xor: data.Xor{},
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

		} else if e, ok := err.(data.YARAError); ok {
			if e.Unwrap() != data.ErrInvalidStringModifierCombo {
				t.Errorf(
					`%s failed with "%s"; expected to fail with "%s"`,
					rule.Identifier,
					err,
					data.ErrInvalidStringModifierCombo)
			}

		} else {
			t.Errorf(`%s failed with error %s`, rule.Identifier, err)
		}
	}
}
