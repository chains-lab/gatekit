package httpkit

import (
	"fmt"
	"io"
	"net/http"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/google/jsonapi"
	"github.com/pkg/errors"
)

type ResponseErrorInput struct {
	// Unique identifier for the error
	ErrorID string

	// Unique identifier for the request (correlation ID)
	RequestID string

	// HTTP status code applicable to this problem, as a string ("400", "500" и т.д.)
	Status int

	// Application-specific error code, expressed as a string value.
	Code string

	// short, human-readable summary of the problem that SHOULD NOT change from occurrence to occurrence of the problem, except for purposes of localization.
	Title string

	// human-readable explanation specific to this occurrence of the problem. Like title, this field’s value can be localized.
	Detail string

	Error error

	// Indicating which URI query parameter caused the error.
	Parameter string

	// JSON Pointer [RFC6901] to the value in the request document that caused the error [e.g. "/data" for a primary data object, or "/data/attributes/title" for a specific attribute]. This MUST point to a value in the request document that exists; if it doesn’t, the client SHOULD simply ignore the pointer
	Pointer string

	// Query string to indicate the specific query parameter that caused the error.
	Query string
}

func ResponseError(input ResponseErrorInput) []*jsonapi.ErrorObject {
	cause := errors.Cause(input.Error)
	if cause == io.EOF {
		return []*jsonapi.ErrorObject{
			{
				Title:  http.StatusText(http.StatusBadRequest),
				Status: fmt.Sprintf("%d", http.StatusBadRequest),
				Detail: "Request body were expected",
			},
		}
	}

	switch cause := cause.(type) {
	case validation.Errors:
		return toJsonapiErrors(cause, input)
	default:
		meta := &map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		if input.ErrorID != "" {
			(*meta)["error_id"] = input.ErrorID
		}

		if input.RequestID != "" {
			(*meta)["request_id"] = input.RequestID
		}

		if input.Parameter != "" {
			(*meta)["parameter"] = input.Parameter
		}

		if input.Pointer != "" {
			(*meta)["pointer"] = input.Pointer
		}

		if input.Query != "" {
			(*meta)["query"] = input.Query
		}

		if input.Status == 0 {
			input.Status = http.StatusInternalServerError
		}

		if http.StatusText(input.Status) == "" {
			input.Status = http.StatusInternalServerError
		}

		if input.Title == "" {
			input.Title = http.StatusText(input.Status)
		}

		if input.Code == "" {
			input.Code = http.StatusText(input.Status)
		}

		eo := &jsonapi.ErrorObject{
			ID:     input.ErrorID,
			Code:   input.Code,
			Status: fmt.Sprintf("%v", input.Status),
			Title:  input.Title,
			Detail: input.Detail,
			Meta:   meta,
		}

		if input.Error != nil {
			eo.Detail = input.Error.Error()
		}

		return []*jsonapi.ErrorObject{eo}
	}
}

func toJsonapiErrors(m map[string]error, input ResponseErrorInput) []*jsonapi.ErrorObject {
	errs := make([]*jsonapi.ErrorObject, 0, len(m))
	for key, value := range m {

		meta := &map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}

		if input.RequestID != "" {
			(*meta)["request_id"] = input.RequestID
		}

		if input.ErrorID != "" {
			(*meta)["error_id"] = input.ErrorID
		}

		if input.Pointer != "" {
			(*meta)["pointer"] = input.Pointer
		}

		if input.Query != "" {
			(*meta)["query"] = input.Query
		}

		if input.Parameter != "" {
			(*meta)["parameter"] = key
		}

		if input.Status == 0 {
			input.Status = http.StatusBadRequest
		}

		if input.Title == "" {
			input.Title = http.StatusText(input.Status)
		}

		if input.Code == "" {
			input.Code = http.StatusText(input.Status)
		}

		e := &jsonapi.ErrorObject{
			ID:     input.ErrorID,
			Code:   input.Code,
			Status: fmt.Sprintf("%v", input.Status),
			Title:  input.Title,
			Detail: value.Error(),
		}

		errs = append(errs, e)
	}
	return errs
}
