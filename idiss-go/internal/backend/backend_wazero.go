//go:build idisswasm && !idissnative

package backend

import "github.com/Concordium/concordium-base/idiss-go/internal/wasm"

func ValidateRequestV1(global, ipInfo, arsInfos, request []byte) error {
	return wasm.ValidateRequestV1(global, ipInfo, arsInfos, request)
}

func CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey []byte) ([]byte, error) {
	return wasm.CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey)
}

func ValidateRecoveryRequest(global, ipInfo, request []byte) error {
	return wasm.ValidateRecoveryRequest(global, ipInfo, request)
}
