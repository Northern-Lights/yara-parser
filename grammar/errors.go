package grammar

import "fmt"

func recoverParse(err *error) {
	currentRule = nil
	if r := recover(); r != nil {
		e := fmt.Errorf("%s", r)
		*err = e
	}
}
