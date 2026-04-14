//go:build idisswasm

package wasm

import (
	"encoding/binary"
	"fmt"
)

type allocation struct {
	ptr int32
	len int32
	cap int32
}

func allocateBytes(inst *instance, data []byte) (allocation, error) {
	if len(data) == 0 {
		return allocation{}, nil
	}

	alloc, err := allocate(inst, int32(len(data)))
	if err != nil {
		return allocation{}, err
	}
	if ok := inst.memory.Write(uint32(alloc.ptr), data); !ok {
		freeAllocation(inst, alloc)
		return allocation{}, fmt.Errorf("write %d bytes to wasm memory", len(data))
	}
	return allocation{ptr: alloc.ptr, len: int32(len(data)), cap: int32(len(data))}, nil
}

func allocateI32(inst *instance) (allocation, error) {
	return allocate(inst, 4)
}

func allocate(inst *instance, size int32) (allocation, error) {
	if size <= 0 {
		return allocation{}, nil
	}

	results, err := inst.alloc.Call(inst.ctx, uint64(uint32(size)))
	if err != nil {
		return allocation{}, fmt.Errorf("call alloc: %w", err)
	}
	if len(results) != 1 {
		return allocation{}, fmt.Errorf("alloc returned %d values", len(results))
	}
	ptr := int32(results[0])
	if ptr == 0 {
		return allocation{}, fmt.Errorf("alloc returned null pointer for size %d", size)
	}
	return allocation{ptr: ptr, len: size, cap: size}, nil
}

func freeAllocation(inst *instance, alloc allocation) error {
	if alloc.ptr == 0 {
		return nil
	}
	_, err := inst.free.Call(inst.ctx, uint64(uint32(alloc.ptr)), uint64(uint32(alloc.len)), uint64(uint32(alloc.cap)))
	if err != nil {
		return fmt.Errorf("call free: %w", err)
	}
	return nil
}

func readI32(inst *instance, ptr int32) (int32, error) {
	data, ok := inst.memory.Read(uint32(ptr), 4)
	if !ok {
		return 0, fmt.Errorf("read i32 from wasm memory at %d", ptr)
	}
	return int32(binary.LittleEndian.Uint32(data)), nil
}

func readBytes(inst *instance, ptr, length int32) ([]byte, error) {
	if ptr == 0 || length == 0 {
		return []byte{}, nil
	}
	data, ok := inst.memory.Read(uint32(ptr), uint32(length))
	if !ok {
		return nil, fmt.Errorf("read %d bytes from wasm memory at %d", length, ptr)
	}
	copyBytes := make([]byte, length)
	copy(copyBytes, data)
	return copyBytes, nil
}
