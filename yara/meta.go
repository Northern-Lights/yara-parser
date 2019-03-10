package yara

import (
	"fmt"
	"strings"
)

// Metas are slices of Meta. A single Meta may be duplicated within Metas.
type Metas []Meta

// RuleString for Metas returns the "meta:" section in the YARA rule
func (ms *Metas) RuleString() (out string, err error) {
	if ms == nil || len(*ms) == 0 {
		return
	}

	var b strings.Builder
	b.WriteString("meta:\n")

	for _, m := range *ms {
		meta, e := m.RuleString()
		if e != nil {
			err = e
			return
		}
		b.WriteString("  ") // TODO: make indent customizable
		b.WriteString(meta)
		b.WriteRune('\n')
	}

	out = b.String()
	return
}

// A Meta is a simple key/value pair. Val should be restricted to
// int, string, and bool.
type Meta struct {
	Key string      `json:"key"`
	Val interface{} `json:"val"`
}

// RuleString for Meta returns the string representation of the key/value pair
func (m *Meta) RuleString() (out string, err error) {
	switch val := m.Val.(type) {
	case string:
		out = fmt.Sprintf(`%s = "%s"`, m.Key, val)

	case int64, bool:
		out = fmt.Sprintf(`%s = %v`, m.Key, val)

	case float64:
		// This is a bit tricky... val is interface{} and JSON unmarshals it
		// as float64... So ensure decimal part is zero and treat as int64.
		n := int64(val)
		check := val - float64(n) // This should be 0.0 if it was int64
		if check != 0.0 {
			err = fmt.Errorf(`Unsupported meta value type "%T"`, val)
			return
		}
		out = fmt.Sprintf(`%s = %v`, m.Key, val)

	default:
		err = fmt.Errorf(`Unsupported meta value type "%s"`, val)
	}

	return
}
