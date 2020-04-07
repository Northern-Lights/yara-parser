package grammar

import "fmt"

func recoverParse(err *error) {
	if r := recover(); r != nil {
		if e, ok := r.(error); ok {
			*err = e
		} else {
			*err = fmt.Errorf("%s", r)
		}
	}
}
