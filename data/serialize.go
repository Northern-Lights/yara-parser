package data

import (
	"fmt"
	"io"
	"strings"
)

// Serialize builds the Yara rule
func (rule *Rule) Serialize(output io.Writer) {
	if rule.Modifiers.Global {
		fmt.Fprintf(output, "global ")
	} else if rule.Modifiers.Private {
		fmt.Fprintf(output, "private ")
	}

	fmt.Fprintf(output, "rule %s ", rule.Identifier)
	if len(rule.Tags) > 0 {
		fmt.Fprintf(output, ": %s ", strings.Join(rule.Tags, " "))
	}

	fmt.Fprintf(output, "{ \n")
	if len(rule.Meta) > 0 {
		fmt.Fprintf(output, "  meta:\n")
		for _, meta := range rule.Meta {
			if _, ok := meta.Val.(string); ok {
				fmt.Fprintf(output, "    %s = \"%s\"\n", meta.Key, meta.Val)
			}
			if _, ok := meta.Val.(int64); ok {
				fmt.Fprintf(output, "    %s = %d\n", meta.Key, meta.Val)
			}
			if val, ok := meta.Val.(bool); ok {
				if val {
					fmt.Fprintf(output, "    %s = true\n", meta.Key)
				} else {
					fmt.Fprintf(output, "    %s = false\n", meta.Key)
				}
			}
		}
		fmt.Fprintf(output, "\n")
	}

	if len(rule.Strings) > 0 {
		fmt.Fprintf(output, "  strings:\n")
		for _, s := range rule.Strings {
			if s.Type == TypeString {
				fmt.Fprintf(output, "    %s = \"%s\"", s.ID, s.Text)
			} else if s.Type == TypeRegex {
				fmt.Fprintf(output, "    %s = /%s/", s.ID, s.Text)
			} else if s.Type == TypeHexString {
				fmt.Fprintf(output, "    %s = { %s }", s.ID, s.Text)
			}
			if s.Modifiers.ASCII {
				fmt.Fprintf(output, " ascii")
			}
			if s.Modifiers.Wide {
				fmt.Fprintf(output, " wide")
			}
			if s.Modifiers.Nocase {
				fmt.Fprintf(output, " nocase")
			}
			if s.Modifiers.Fullword {
				fmt.Fprintf(output, " fullword")
			}

			if s.Modifiers.I {
				fmt.Fprintf(output, "i")
			}
			if s.Modifiers.S {
				fmt.Fprintf(output, "s")
			}

			fmt.Fprintf(output, "\n")
		}
		fmt.Fprintf(output, "\n")
	}

	fmt.Fprintf(output, "  condition:\n    %s\n}\n\n", rule.Condition)
}
