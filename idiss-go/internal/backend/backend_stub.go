//go:build !idissnative && !idisswasm

package backend

import "errors"

var errBackendNotEnabled = errors.New("idiss backend is not enabled; build with cgo and idissnative, or with idisswasm")

func ValidateRequestV1(_, _, _, _ []byte) error {
	return errBackendNotEnabled
}

func CreateIdentityObjectV1(_, _, _, _ []byte) ([]byte, error) {
	return nil, errBackendNotEnabled
}

func ValidateRecoveryRequest(_, _, _ []byte) error {
	return errBackendNotEnabled
}
