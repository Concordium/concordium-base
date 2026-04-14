//go:build idisswasm

package wasm

import (
	"errors"
	"fmt"
)

type moduleError struct {
	message string
}

func (e moduleError) Error() string {
	return e.message
}

func ValidateRequestV1(global, ipInfo, arsInfos, request []byte) error {
	inst, err := load()
	if err != nil {
		return err
	}

	globalAlloc, err := allocateBytes(inst, global)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, globalAlloc)

	ipInfoAlloc, err := allocateBytes(inst, ipInfo)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, ipInfoAlloc)

	arsInfosAlloc, err := allocateBytes(inst, arsInfos)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, arsInfosAlloc)

	requestAlloc, err := allocateBytes(inst, request)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, requestAlloc)

	outLengthAlloc, err := allocateI32(inst)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, outLengthAlloc)

	outCapacityAlloc, err := allocateI32(inst)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, outCapacityAlloc)

	results, err := inst.validateRequest.Call(
		inst.ctx,
		uint64(uint32(globalAlloc.ptr)), uint64(uint32(globalAlloc.len)),
		uint64(uint32(ipInfoAlloc.ptr)), uint64(uint32(ipInfoAlloc.len)),
		uint64(uint32(arsInfosAlloc.ptr)), uint64(uint32(arsInfosAlloc.len)),
		uint64(uint32(requestAlloc.ptr)), uint64(uint32(requestAlloc.len)),
		uint64(uint32(outLengthAlloc.ptr)), uint64(uint32(outCapacityAlloc.ptr)),
	)
	if err != nil {
		return fmt.Errorf("call validate_request_v1_wasm: %w", err)
	}
	if len(results) != 1 {
		return fmt.Errorf("validate_request_v1_wasm returned %d values", len(results))
	}

	resultPtr := int32(results[0])
	if resultPtr == 0 {
		return nil
	}

	outLength, err := readI32(inst, outLengthAlloc.ptr)
	if err != nil {
		return err
	}
	outCapacity, err := readI32(inst, outCapacityAlloc.ptr)
	if err != nil {
		return err
	}
	message, err := readBytes(inst, resultPtr, outLength)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, allocation{ptr: resultPtr, len: outLength, cap: outCapacity})

	return moduleError{message: string(message)}
}

func CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey []byte) ([]byte, error) {
	inst, err := load()
	if err != nil {
		return nil, err
	}

	ipInfoAlloc, err := allocateBytes(inst, ipInfo)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, ipInfoAlloc)

	requestAlloc, err := allocateBytes(inst, request)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, requestAlloc)

	attributesAlloc, err := allocateBytes(inst, attributes)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, attributesAlloc)

	ipPrivateKeyAlloc, err := allocateBytes(inst, ipPrivateKey)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, ipPrivateKeyAlloc)

	outLengthAlloc, err := allocateI32(inst)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, outLengthAlloc)

	outCapacityAlloc, err := allocateI32(inst)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, outCapacityAlloc)

	outSuccessAlloc, err := allocateI32(inst)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, outSuccessAlloc)

	results, err := inst.createIdentity.Call(
		inst.ctx,
		uint64(uint32(ipInfoAlloc.ptr)), uint64(uint32(ipInfoAlloc.len)),
		uint64(uint32(requestAlloc.ptr)), uint64(uint32(requestAlloc.len)),
		uint64(uint32(attributesAlloc.ptr)), uint64(uint32(attributesAlloc.len)),
		uint64(uint32(ipPrivateKeyAlloc.ptr)), uint64(uint32(ipPrivateKeyAlloc.len)),
		uint64(uint32(outLengthAlloc.ptr)), uint64(uint32(outCapacityAlloc.ptr)), uint64(uint32(outSuccessAlloc.ptr)),
	)
	if err != nil {
		return nil, fmt.Errorf("call create_identity_object_v1_wasm: %w", err)
	}
	if len(results) != 1 {
		return nil, fmt.Errorf("create_identity_object_v1_wasm returned %d values", len(results))
	}

	resultPtr := int32(results[0])
	if resultPtr == 0 {
		return nil, errors.New("create_identity_object_v1_wasm returned a null pointer")
	}

	outLength, err := readI32(inst, outLengthAlloc.ptr)
	if err != nil {
		return nil, err
	}
	outCapacity, err := readI32(inst, outCapacityAlloc.ptr)
	if err != nil {
		return nil, err
	}
	outSuccess, err := readI32(inst, outSuccessAlloc.ptr)
	if err != nil {
		return nil, err
	}

	response, err := readBytes(inst, resultPtr, outLength)
	if err != nil {
		return nil, err
	}
	defer freeAllocationIgnoreError(inst, allocation{ptr: resultPtr, len: outLength, cap: outCapacity})

	switch outSuccess {
	case 1:
		return response, nil
	case -1:
		return nil, moduleError{message: string(response)}
	default:
		return nil, fmt.Errorf("create_identity_object_v1_wasm returned unknown status %d", outSuccess)
	}
}

func ValidateRecoveryRequest(global, ipInfo, request []byte) error {
	inst, err := load()
	if err != nil {
		return err
	}

	globalAlloc, err := allocateBytes(inst, global)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, globalAlloc)

	ipInfoAlloc, err := allocateBytes(inst, ipInfo)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, ipInfoAlloc)

	requestAlloc, err := allocateBytes(inst, request)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, requestAlloc)

	outLengthAlloc, err := allocateI32(inst)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, outLengthAlloc)

	outCapacityAlloc, err := allocateI32(inst)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, outCapacityAlloc)

	results, err := inst.validateRecovery.Call(
		inst.ctx,
		uint64(uint32(globalAlloc.ptr)), uint64(uint32(globalAlloc.len)),
		uint64(uint32(ipInfoAlloc.ptr)), uint64(uint32(ipInfoAlloc.len)),
		uint64(uint32(requestAlloc.ptr)), uint64(uint32(requestAlloc.len)),
		uint64(uint32(outLengthAlloc.ptr)), uint64(uint32(outCapacityAlloc.ptr)),
	)
	if err != nil {
		return fmt.Errorf("call validate_recovery_request_wasm: %w", err)
	}
	if len(results) != 1 {
		return fmt.Errorf("validate_recovery_request_wasm returned %d values", len(results))
	}

	resultPtr := int32(results[0])
	if resultPtr == 0 {
		return nil
	}

	outLength, err := readI32(inst, outLengthAlloc.ptr)
	if err != nil {
		return err
	}
	outCapacity, err := readI32(inst, outCapacityAlloc.ptr)
	if err != nil {
		return err
	}
	message, err := readBytes(inst, resultPtr, outLength)
	if err != nil {
		return err
	}
	defer freeAllocationIgnoreError(inst, allocation{ptr: resultPtr, len: outLength, cap: outCapacity})

	return moduleError{message: string(message)}
}

func freeAllocationIgnoreError(inst *instance, alloc allocation) {
	_ = freeAllocation(inst, alloc)
}
