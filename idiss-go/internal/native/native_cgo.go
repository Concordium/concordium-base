//go:build cgo && idissnative

package native

/*
#include <stdint.h>
#include <stdlib.h>

const uint8_t* validate_request_v1_go(
	const uint8_t* ctx_ptr,
	int32_t ctx_len,
	const uint8_t* ip_info_ptr,
	int32_t ip_info_len,
	const uint8_t* ars_infos_ptr,
	int32_t ars_len,
	const uint8_t* request_ptr,
	int32_t request_len,
	int32_t* out_length,
	int32_t* out_capacity
);

const uint8_t* create_identity_object_v1_go(
	const uint8_t* ip_info_ptr,
	int32_t ip_info_len,
	const uint8_t* request_ptr,
	int32_t request_len,
	const uint8_t* alist_ptr,
	int32_t alist_len,
	const uint8_t* ip_private_key_ptr,
	int32_t ip_private_key_len,
	int32_t* out_length,
	int32_t* out_capacity,
	int32_t* out_success
);

const uint8_t* validate_recovery_request_go(
	const uint8_t* ctx_ptr,
	int32_t ctx_len,
	const uint8_t* ip_info_ptr,
	int32_t ip_info_len,
	const uint8_t* request_ptr,
	int32_t request_len,
	int32_t* out_length,
	int32_t* out_capacity
);

void free_array_len_cap(uint8_t* ptr, uint64_t len, uint64_t cap);
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// NativeError is an error string returned by the Rust library.
type NativeError struct {
	Message string
}

func (e NativeError) Error() string {
	return e.Message
}

// ValidateRequestV1 validates a version 1 request through the native library.
func ValidateRequestV1(global, ipInfo, arsInfos, request []byte) error {
	var outLength C.int32_t
	var outCapacity C.int32_t

	ptr := C.validate_request_v1_go(
		bytePtr(global), C.int32_t(len(global)),
		bytePtr(ipInfo), C.int32_t(len(ipInfo)),
		bytePtr(arsInfos), C.int32_t(len(arsInfos)),
		bytePtr(request), C.int32_t(len(request)),
		&outLength, &outCapacity,
	)
	if ptr == nil {
		return nil
	}

	message, err := copyAndFree(ptr, outLength, outCapacity)
	if err != nil {
		return err
	}
	return NativeError{Message: string(message)}
}

// CreateIdentityObjectV1 creates a version 1 identity object through the native library.
func CreateIdentityObjectV1(ipInfo, attributes, request, ipPrivateKey []byte) ([]byte, error) {
	var outLength C.int32_t
	var outCapacity C.int32_t
	var outSuccess C.int32_t

	ptr := C.create_identity_object_v1_go(
		bytePtr(ipInfo), C.int32_t(len(ipInfo)),
		bytePtr(request), C.int32_t(len(request)),
		bytePtr(attributes), C.int32_t(len(attributes)),
		bytePtr(ipPrivateKey), C.int32_t(len(ipPrivateKey)),
		&outLength, &outCapacity, &outSuccess,
	)
	if ptr == nil {
		return nil, errors.New("create_identity_object_v1_go returned a null pointer")
	}

	response, err := copyAndFree(ptr, outLength, outCapacity)
	if err != nil {
		return nil, err
	}

	switch outSuccess {
	case 1:
		return response, nil
	case -1:
		return nil, NativeError{Message: string(response)}
	default:
		return nil, fmt.Errorf("create_identity_object_v1_go returned unknown status %d", int32(outSuccess))
	}
}

// ValidateRecoveryRequest validates a recovery request through the native library.
func ValidateRecoveryRequest(global, ipInfo, request []byte) error {
	var outLength C.int32_t
	var outCapacity C.int32_t

	ptr := C.validate_recovery_request_go(
		bytePtr(global), C.int32_t(len(global)),
		bytePtr(ipInfo), C.int32_t(len(ipInfo)),
		bytePtr(request), C.int32_t(len(request)),
		&outLength, &outCapacity,
	)
	if ptr == nil {
		return nil
	}

	message, err := copyAndFree(ptr, outLength, outCapacity)
	if err != nil {
		return err
	}
	return NativeError{Message: string(message)}
}

func bytePtr(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0]))
}

func copyAndFree(ptr *C.uint8_t, outLength, outCapacity C.int32_t) ([]byte, error) {
	length := int64(outLength)
	capacity := int64(outCapacity)
	if length < 0 || capacity < 0 {
		return nil, fmt.Errorf("native returned negative length/capacity: len=%d cap=%d", length, capacity)
	}
	if capacity < length {
		return nil, fmt.Errorf("native returned capacity smaller than length: len=%d cap=%d", length, capacity)
	}

	defer C.free_array_len_cap(ptr, C.uint64_t(length), C.uint64_t(capacity))
	if length == 0 {
		return []byte{}, nil
	}

	return C.GoBytes(unsafe.Pointer(ptr), C.int(length)), nil
}
