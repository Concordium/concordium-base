//go:build (cgo && idissnative) || idisswasm

package idiss_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/Concordium/concordium-base/idiss-go/idiss"
)

type testFixtures struct {
	Global          idiss.Versioned[idiss.GlobalContext]
	IPInfo          idiss.Versioned[idiss.IPInfo]
	ARInfos         idiss.Versioned[map[string]idiss.ARInfo]
	RequestV1       idiss.IDObjectRequestV1
	RecoveryRequest idiss.IDRecoveryWrapper
	Attributes      idiss.AttributeList
	IPSecretKey     string
	IPCDISecretKey  string
}

type identityProviderFixture struct {
	IPSecretKey    string `json:"ipSecretKey"`
	IPCDISecretKey string `json:"ipCdiSecretKey"`
}

func TestValidateRequestV1(t *testing.T) {
	fx := loadFixtures(t)

	err := idiss.ValidateRequestV1(fx.Global, fx.IPInfo, fx.ARInfos, fx.RequestV1)
	if err != nil {
		t.Fatalf("ValidateRequestV1 returned error: %v", err)
	}
}

func TestCreateIdentityObjectV1(t *testing.T) {
	fx := loadFixtures(t)

	response, err := idiss.CreateIdentityObjectV1(fx.IPInfo, fx.Attributes, fx.RequestV1, fx.IPSecretKey)
	if err != nil {
		t.Fatalf("CreateIdentityObjectV1 returned error: %v", err)
	}

	got := response.ARRecord.Value.RevocationThreshold
	want := fx.RequestV1.IDObjectRequest.Value.ChoiceARData.Threshold
	if got != want {
		t.Fatalf("unexpected revocation threshold: got %d want %d", got, want)
	}

	if response.IDObj.V != fx.RequestV1.IDObjectRequest.V {
		t.Fatalf("unexpected identity object version: got %d want %d", response.IDObj.V, fx.RequestV1.IDObjectRequest.V)
	}

	if response.IDObj.Value.Signature == "" {
		t.Fatal("identity object signature is empty")
	}
	if response.ARRecord.Value.IDCredPub != fx.RequestV1.IDObjectRequest.Value.IDCredPub {
		t.Fatal("ar record idCredPub does not match request")
	}
}

func TestValidateRecoveryRequest(t *testing.T) {
	fx := loadFixtures(t)
	now := time.Unix(int64(fx.RecoveryRequest.IDRecoveryRequest.Value.Timestamp), 0)

	err := idiss.ValidateRecoveryRequest(fx.Global, fx.IPInfo, fx.RecoveryRequest, now)
	if err != nil {
		t.Fatalf("ValidateRecoveryRequest returned error: %v", err)
	}
}

func TestValidateRecoveryRequestRejectsInvalidTimestamp(t *testing.T) {
	fx := loadFixtures(t)
	now := time.Unix(int64(fx.RecoveryRequest.IDRecoveryRequest.Value.Timestamp), 0).Add(idiss.TimestampDelta + time.Second)

	err := idiss.ValidateRecoveryRequest(fx.Global, fx.IPInfo, fx.RecoveryRequest, now)
	if !errors.Is(err, idiss.ErrInvalidRecoveryTimestamp) {
		t.Fatalf("expected invalid recovery timestamp error, got %v", err)
	}
}

func TestValidateRecoveryRequestRejectsInvalidProof(t *testing.T) {
	fx := loadFixtures(t)
	now := time.Unix(int64(fx.RecoveryRequest.IDRecoveryRequest.Value.Timestamp), 0)
	invalid := fx.RecoveryRequest
	invalid.IDRecoveryRequest.Value.Proof = mutateHexString(invalid.IDRecoveryRequest.Value.Proof)

	err := idiss.ValidateRecoveryRequest(fx.Global, fx.IPInfo, invalid, now)
	if err == nil {
		t.Fatal("expected invalid proof error, got nil")
	}
	if errors.Is(err, idiss.ErrInvalidRecoveryTimestamp) {
		t.Fatalf("expected proof validation error, got timestamp error: %v", err)
	}
}

func loadFixtures(t *testing.T) testFixtures {
	t.Helper()
	base := fixtureDir(t)

	var fx testFixtures
	readJSONFixture(t, filepath.Join(base, "global.json"), &fx.Global)
	readJSONFixture(t, filepath.Join(base, "identity_provider.pub.json"), &fx.IPInfo)
	readJSONFixture(t, filepath.Join(base, "anonymity_revokers.json"), &fx.ARInfos)
	readJSONFixture(t, filepath.Join(base, "valid_request_v1.json"), &fx.RequestV1)
	readJSONFixture(t, filepath.Join(base, "id_recovery_request.json"), &fx.RecoveryRequest)
	readJSONFixture(t, filepath.Join(base, "alist.json"), &fx.Attributes)

	var identityProvider identityProviderFixture
	readJSONFixture(t, filepath.Join(repoRoot(t), "identity-provider-service", "data", "identity_provider.json"), &identityProvider)
	fx.IPSecretKey = identityProvider.IPSecretKey
	fx.IPCDISecretKey = identityProvider.IPCDISecretKey
	return fx
}

func readJSONFixture(t *testing.T, path string, out any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", path, err)
	}
}

func fixtureDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "idiss-csharp", "data")
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine current file path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func mutateHexString(s string) string {
	if s == "" {
		return "0"
	}
	if s[len(s)-1] == '0' {
		return s[:len(s)-1] + "1"
	}
	return s[:len(s)-1] + "0"
}
