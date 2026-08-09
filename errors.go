package p2pstore

import (
	"context"
	"errors"
	"fmt"
)

// ErrorCode is stable across the Go API and wire protocol.
type ErrorCode string

const (
	// CodeInvalidArgument indicates malformed names, options, frames, or other
	// caller-controlled input.
	CodeInvalidArgument ErrorCode = "invalid_argument"
	// CodeNotFound indicates that an object is absent or expired.
	CodeNotFound ErrorCode = "not_found"
	// CodeQuotaExceeded indicates that a Put would exceed provider MaxBytes.
	CodeQuotaExceeded ErrorCode = "quota_exceeded"
	// CodeUnavailable indicates a signaling, ICE, QUIC, or provider outage.
	CodeUnavailable ErrorCode = "unavailable"
	// CodeUnauthenticated indicates rejected signaling identity, capability, or
	// TLS certificate fingerprint.
	CodeUnauthenticated ErrorCode = "unauthenticated"
	// CodeInternal indicates an unexpected provider or protocol failure.
	CodeInternal ErrorCode = "internal"
)

// Error is the typed error returned by all p2pstore implementations.
type Error struct {
	// Code is the stable, machine-readable failure class.
	Code ErrorCode `json:"code"`
	// Message is a human-readable explanation suitable for logs and clients.
	Message string `json:"message"`
	// Err retains the local cause for errors.Is/errors.As. It is never sent on
	// the wire or encoded as JSON.
	Err error `json:"-"`
}

// Error formats the stable code and human-readable message.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return fmt.Sprintf("p2pstore %s: %s", e.Code, e.Message)
	}
	return "p2pstore " + string(e.Code)
}

// Unwrap returns the local underlying cause, if one was retained.
func (e *Error) Unwrap() error { return e.Err }

// IsCode reports whether err or an error it wraps has the given code.
func IsCode(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.Code == code
}

// errorf constructs a local typed error without an underlying cause.
func errorf(code ErrorCode, format string, args ...any) error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// normalizeError removes local causes before encoding an error on the wire.
func normalizeError(err error) *Error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return &Error{Code: typed.Code, Message: typed.Message}
	}
	return &Error{Code: CodeInternal, Message: err.Error()}
}

// typedStoreError preserves context and already-typed errors while classifying
// every other provider failure as internal.
func typedStoreError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	return &Error{Code: CodeInternal, Message: err.Error(), Err: err}
}
