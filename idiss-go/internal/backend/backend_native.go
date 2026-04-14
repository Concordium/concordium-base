//go:build cgo && idissnative && !idisswasm

package backend

import "github.com/Concordium/concordium-base/idiss-go/internal/native"

func ValidateRequestV1(global, ipInfo, arsInfos, request []byte) error {
	return native.ValidateRequestV1(global, ipInfo, arsInfos, request)
}

func CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey []byte) ([]byte, error) {
	return native.CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey)
}

func ValidateRecoveryRequest(global, ipInfo, request []byte) error {
	return native.ValidateRecoveryRequest(global, ipInfo, request)
}
