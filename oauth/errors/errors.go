package errors

import "net/http"

type RESTError struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Error   string `json:"error"`
}

func BadRequest(msg string) *RESTError {
	return &RESTError{
		Message: msg,
		Status:  http.StatusBadRequest,
		Error:   http.StatusText(400),
	}
}

func NotFound() *RESTError {
	return &RESTError{
		Message: "No record(s) found",
		Status:  http.StatusNotFound,
		Error:   http.StatusText(404),
	}
}

func InternalServerError() *RESTError {
	return &RESTError{
		Message: "Sorry, something went wrong",
		Status:  http.StatusInternalServerError,
		Error:   http.StatusText(500),
	}
}
