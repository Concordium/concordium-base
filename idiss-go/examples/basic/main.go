package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Concordium/concordium-base/idiss-go/idiss"
)

type identityProviderFixture struct {
	IPSecretKey string `json:"ipSecretKey"`
}

func main() {
	root := repoRoot()
	fixtureDir := filepath.Join(root, "idiss-csharp", "data")

	global := mustReadJSON[idiss.Versioned[idiss.GlobalContext]](filepath.Join(fixtureDir, "global.json"))
	ipInfo := mustReadJSON[idiss.Versioned[idiss.IPInfo]](filepath.Join(fixtureDir, "identity_provider.pub.json"))
	arsInfos := mustReadJSON[idiss.Versioned[map[string]idiss.ARInfo]](filepath.Join(fixtureDir, "anonymity_revokers.json"))
	request := mustReadJSON[idiss.IDObjectRequestV1](filepath.Join(fixtureDir, "valid_request_v1.json"))
	attributes := mustReadJSON[idiss.AttributeList](filepath.Join(fixtureDir, "alist.json"))
	recovery := mustReadJSON[idiss.IDRecoveryWrapper](filepath.Join(fixtureDir, "id_recovery_request.json"))
	provider := mustReadJSON[identityProviderFixture](filepath.Join(root, "identity-provider-service", "data", "identity_provider.json"))

	must(idiss.ValidateRequestV1(global, ipInfo, arsInfos, request))
	creation, err := idiss.CreateIdentityObjectV1(ipInfo, attributes, request, provider.IPSecretKey)
	must(err)

	now := time.Unix(int64(recovery.IDRecoveryRequest.Value.Timestamp), 0)
	must(idiss.ValidateRecoveryRequest(global, ipInfo, recovery, now))

	fmt.Printf("validated request version: %d\n", request.IDObjectRequest.V)
	fmt.Printf("revocation threshold: %d\n", creation.ARRecord.Value.RevocationThreshold)
	fmt.Printf("identity object signature length: %d\n", len(creation.IDObj.Value.Signature))
	fmt.Println("recovery request validated")
}

func mustReadJSON[T any](path string) T {
	data, err := os.ReadFile(path)
	must(err)

	var out T
	must(json.Unmarshal(data, &out))
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("could not determine current file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}
