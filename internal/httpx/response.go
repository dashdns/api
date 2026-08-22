// Package httpx holds the HTTP plumbing shared by every module: the router,
// the middleware chain and the JSON envelope.
package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// ErrorBody is the single error shape returned by every endpoint.
type ErrorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	// Details carries per-field validation messages when present.
	Details map[string]string `json:"details,omitempty"`
}

// Machine-readable values for ErrorBody.Error.
const (
	CodeBadRequest      = "bad_request"
	CodeUnauthorized    = "unauthorized"
	CodeForbidden       = "forbidden"
	CodeNotFound        = "not_found"
	CodeConflict        = "conflict"
	CodeUnsupported     = "unsupported"
	CodePayloadTooLarge = "payload_too_large"
	CodeInternal        = "internal_error"
)

// JSON writes v as an indented JSON body with the given status.
//
// The body is marshalled before the status is written so an encoding failure
// cannot leave a half-written 200 on the wire.
func JSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		slog.ErrorContext(r.Context(), "encoding response failed", "error", err, "path", r.URL.Path)
		http.Error(w, `{"error":"internal_error","message":"failed to encode response"}`, http.StatusInternalServerError)
		return
	}
	body = append(body, '\n')
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// NoContent writes a bare 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Error writes an ErrorBody with the given status.
func Error(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	JSON(w, r, status, ErrorBody{Error: code, Message: message})
}

// Errorf is Error with formatting.
func Errorf(w http.ResponseWriter, r *http.Request, status int, code, format string, args ...any) {
	Error(w, r, status, code, fmt.Sprintf(format, args...))
}

// ValidationError writes a 400 carrying per-field messages.
func ValidationError(w http.ResponseWriter, r *http.Request, message string, details map[string]string) {
	JSON(w, r, http.StatusBadRequest, ErrorBody{
		Error:   CodeBadRequest,
		Message: message,
		Details: details,
	})
}

// Internal logs err and writes a 500 that does not leak internals.
func Internal(w http.ResponseWriter, r *http.Request, err error) {
	slog.ErrorContext(r.Context(), "request failed",
		"error", err,
		"method", r.Method,
		"path", r.URL.Path,
	)
	Error(w, r, http.StatusInternalServerError, CodeInternal, "internal server error")
}

// maxBodyBytes bounds request bodies. Policy payloads are small; anything
// larger is a mistake or an attack.
const maxBodyBytes = 1 << 20 // 1 MiB

// DecodeJSON reads a JSON request body into dst with strict semantics: unknown
// fields are rejected, the body is size-limited, and trailing content after the
// first value is an error. It writes the HTTP error itself and reports whether
// decoding succeeded.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		Errorf(w, r, http.StatusUnsupportedMediaType, CodeUnsupported,
			"Content-Type must be application/json, got %q", ct)
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxErr):
			Errorf(w, r, http.StatusRequestEntityTooLarge, CodePayloadTooLarge,
				"request body exceeds %d bytes", maxBodyBytes)
		case errors.Is(err, io.EOF):
			Error(w, r, http.StatusBadRequest, CodeBadRequest, "request body is empty")
		default:
			Errorf(w, r, http.StatusBadRequest, CodeBadRequest, "malformed JSON body: %v", err)
		}
		return false
	}
	if dec.More() {
		Error(w, r, http.StatusBadRequest, CodeBadRequest, "request body must contain a single JSON object")
		return false
	}
	return true
}

func isJSONContentType(ct string) bool {
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			ct = ct[:i]
			break
		}
	}
	switch trimSpace(ct) {
	case "application/json", "text/json", "application/json; charset=utf-8":
		return true
	default:
		return false
	}
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
