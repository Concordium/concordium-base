//go:build !cgo || !idissnative

package native

import "errors"

// ErrNotImplemented is returned when the native bindings are not enabled.
var ErrNotImplemented = errors.New("idiss native bindings are not enabled; build with cgo and the idissnative tag")

// ValidateRequestV1 validates a version 1 request through the native library.
func ValidateRequestV1(_, _, _, _ []byte) error {
	return ErrNotImplemented
}

// CreateIdentityObjectV1 creates a version 1 identity object through the native library.
func CreateIdentityObjectV1(_, _, _, _ []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}

// ValidateRecoveryRequest validates a recovery request through the native library.
func ValidateRecoveryRequest(_, _, _ []byte) error {
	return ErrNotImplemented
}
