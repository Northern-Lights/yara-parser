package tests

import (
	"fmt"
	"testing"
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
		} /* else if !errors.Is(err, data.ErrInvalidStringModifierCombo) {
			t.Errorf(`rule %s failed with "%s"; should have failed with "%s"`,
				ruleName, err, data.ErrInvalidStringModifierCombo)
		}*/
	}
}
