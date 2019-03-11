package yara

import "fmt"

type Range struct {
	Start PrimaryExpression
	End   PrimaryExpression
}

func (r Range) RuleString() (out string, err error) {
	if r.Start == nil || r.End == nil {
		err = fmt.Errorf(`yara: nil PrimaryExpression in range`)
		return
	}

	start, err := r.Start.RuleString()
	if err != nil {
		return
	}
	end, err := r.End.RuleString()
	if err != nil {
		return
	}

	out = fmt.Sprintf(`(%s..%s)`, start, end)

	return
}
