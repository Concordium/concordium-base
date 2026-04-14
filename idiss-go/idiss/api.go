package idiss

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Concordium/concordium-base/idiss-go/internal/backend"
)

// TimestampDelta is the accepted timestamp window for recovery requests.
const TimestampDelta = time.Minute

// ErrInvalidRecoveryTimestamp is returned when a recovery proof timestamp is outside the accepted window.
var ErrInvalidRecoveryTimestamp = errors.New("invalid recovery timestamp")

// ValidateRequestV1 validates a version 1 identity object request.
func ValidateRequestV1(
	global Versioned[GlobalContext],
	ipInfo Versioned[IPInfo],
	arsInfos Versioned[map[string]ARInfo],
	request IDObjectRequestV1,
) error {
	globalBytes, err := json.Marshal(global)
	if err != nil {
		return fmt.Errorf("marshal global context: %w", err)
	}
	ipInfoBytes, err := json.Marshal(ipInfo)
	if err != nil {
		return fmt.Errorf("marshal ip info: %w", err)
	}
	arsInfosBytes, err := json.Marshal(arsInfos)
	if err != nil {
		return fmt.Errorf("marshal ars infos: %w", err)
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	if err := backend.ValidateRequestV1(globalBytes, ipInfoBytes, arsInfosBytes, requestBytes); err != nil {
		return fmt.Errorf("validate request v1: %w", err)
	}
	return nil
}

// CreateIdentityObjectV1 creates the v1 identity object and revocation record.
func CreateIdentityObjectV1(
	ipInfo Versioned[IPInfo],
	attributes AttributeList,
	request IDObjectRequestV1,
	ipPrivateKey string,
) (IdentityCreationV1, error) {
	ipInfoBytes, err := json.Marshal(ipInfo)
	if err != nil {
		return IdentityCreationV1{}, fmt.Errorf("marshal ip info: %w", err)
	}
	attributeBytes, err := json.Marshal(attributes)
	if err != nil {
		return IdentityCreationV1{}, fmt.Errorf("marshal attribute list: %w", err)
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return IdentityCreationV1{}, fmt.Errorf("marshal request: %w", err)
	}

	responseBytes, err := backend.CreateIdentityObjectV1(ipInfoBytes, attributeBytes, requestBytes, []byte(ipPrivateKey))
	if err != nil {
		return IdentityCreationV1{}, fmt.Errorf("create identity object v1: %w", err)
	}

	var response IdentityCreationV1
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return IdentityCreationV1{}, fmt.Errorf("unmarshal identity creation v1 response: %w", err)
	}
	return response, nil
}

// ValidateRecoveryRequest validates a recovery request after checking its timestamp window locally.
func ValidateRecoveryRequest(
	global Versioned[GlobalContext],
	ipInfo Versioned[IPInfo],
	request IDRecoveryWrapper,
	now time.Time,
) error {
	if !recoveryTimestampValid(request.IDRecoveryRequest.Value.Timestamp, now) {
		return ErrInvalidRecoveryTimestamp
	}

	globalBytes, err := json.Marshal(global)
	if err != nil {
		return fmt.Errorf("marshal global context: %w", err)
	}
	ipInfoBytes, err := json.Marshal(ipInfo)
	if err != nil {
		return fmt.Errorf("marshal ip info: %w", err)
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	if err := backend.ValidateRecoveryRequest(globalBytes, ipInfoBytes, requestBytes); err != nil {
		return fmt.Errorf("validate recovery request: %w", err)
	}
	return nil
}

func recoveryTimestampValid(proofTimestamp uint64, now time.Time) bool {
	nowUnix := now.Unix()
	if nowUnix < 0 {
		return false
	}
	nowTimestamp := uint64(nowUnix)
	deltaSeconds := uint64(TimestampDelta / time.Second)
	minTimestamp := nowTimestamp - min(nowTimestamp, deltaSeconds)
	maxTimestamp := nowTimestamp + deltaSeconds
	return proofTimestamp >= minTimestamp && proofTimestamp <= maxTimestamp
}
