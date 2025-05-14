package jsonkit

import (
	"fmt"

	validation "github.com/go-ozzo/ozzo-validation/v4"
)

func NewDecodeError(what string, err error) error {
	return validation.Errors{
		what: fmt.Errorf("decode request %s: %w", what, err),
	}
}
