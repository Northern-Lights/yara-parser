package data

import "fmt"

// YARAError can be used to wrap an error type and a message to go along with it
type YARAError struct {
	err error
	msg string
}

func NewYARAError(err error, msg string) YARAError {
	return YARAError{
		err: err,
		msg: msg,
	}
}

func (e YARAError) Error() string {
	return fmt.Sprintf(`%s: %s`, e.err, e.msg)
}

func (e YARAError) Unwrap() error {
	return e.err
}
