// Stringer implementations for each type

package data

import (
	"fmt"
)

// String for RuleSet returns the name of the file
func (rs RuleSet) String() string {
	return rs.File
}

// String for Rule returns the rule ID
func (r Rule) String() string {
	return r.Identifier
}

// String for Metas returns a string representation of the keys/values
func (ms Metas) String() string {
	mets := make([]string, len(ms))
	for i, m := range ms {
		mets[i] = m.String()
	}
	return fmt.Sprintf("%v", mets)
}

// String for Meta returns a string representation of the key/value
func (m Meta) String() string {
	switch v := m.Val.(type) {
	case string:
		return fmt.Sprintf(`%s/"%v"`, m.Key, v)
	case int64, bool:
		return fmt.Sprintf(`%s/%v`, m.Key, v)
	}
	return fmt.Sprintf("%s/", m.Key)
}

// String for Strings returns a string representation of the String IDs
func (ss Strings) String() string {
	strs := make([]string, len(ss))
	for i, s := range ss {
		strs[i] = s.ID
	}
	return fmt.Sprintf("%v", strs)
}

// String returns the identifier of the String
func (s String) String() string {
	return s.ID
}

func (t StringType) String() string {
	switch t {
	case TypeString:
		return "string"

	case TypeHexString:
		return "hex"

	case TypeRegex:
		return "regex"
	}

	return "unknown"
}

// String for StringModifiers returns a string representation of the modifiers
func (m StringModifiers) String() string {
	mods := make([]string, 0, 6)
	if m.Nocase {
		mods = append(mods, "nocase")
	}
	if m.ASCII {
		mods = append(mods, "ascii")
	}
	if m.Wide {
		mods = append(mods, "wide")
	}
	if m.Fullword {
		mods = append(mods, "fullword")
	}
	if m.Private {
		mods = append(mods, "private")
	}
	if m.Xor != nil {
		xor := m.Xor.String()
		if xor != "" {
			mods = append(mods, xor)
		}
	}
	if m.I {
		mods = append(mods, "insensitive")
	}
	if m.S {
		mods = append(mods, "dotall")
	}
	return fmt.Sprintf("%v", mods)
}

// String returns the string representation of the base64 modifier
func (b64 Base64) String() string {
	s, err := b64.Serialize()
	if err != nil {
		return ""
	}
	return s
}

// String returns the base-10 representation of the underlying int64
func (d Dec) String() string {
	return fmt.Sprintf("%d", d.Value())
}

// String returns the base-8 representation of the underlying int64
func (o Oct) String() string {
	return fmt.Sprintf("0o%o", o.Value())
}

// String returns the base-16 representation of the underlying int64
func (h Hex) String() string {
	return fmt.Sprintf("0x%x", h.Value())
}

func (xor Xor) String() string {
	s, err := xor.Serialize()
	if err != nil {
		return ""
	}
	return s
}
