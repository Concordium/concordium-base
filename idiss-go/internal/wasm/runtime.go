//go:build idisswasm

package wasm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const wasmPathEnv = "IDISS_WASM_PATH"

type instance struct {
	ctx              context.Context
	runtime          wazero.Runtime
	module           api.Module
	memory           api.Memory
	alloc            api.Function
	free             api.Function
	validateRequest  api.Function
	createIdentity   api.Function
	validateRecovery api.Function
}

var (
	loadOnce     sync.Once
	loadedModule *instance
	loadErr      error
)

func load() (*instance, error) {
	loadOnce.Do(func() {
		ctx := context.Background()
		r := wazero.NewRuntime(ctx)
		if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
			loadErr = fmt.Errorf("instantiate wasi: %w", err)
			_ = r.Close(ctx)
			return
		}

		wasmBytes, err := os.ReadFile(wasmPath())
		if err != nil {
			loadErr = fmt.Errorf("read wasm module: %w", err)
			_ = r.Close(ctx)
			return
		}

		module, err := r.Instantiate(ctx, wasmBytes)
		if err != nil {
			loadErr = fmt.Errorf("instantiate wasm module: %w", err)
			_ = r.Close(ctx)
			return
		}

		memory := module.Memory()
		if memory == nil {
			loadErr = fmt.Errorf("wasm module does not export memory")
			_ = module.Close(ctx)
			_ = r.Close(ctx)
			return
		}

		inst := &instance{
			ctx:              ctx,
			runtime:          r,
			module:           module,
			memory:           memory,
			alloc:            module.ExportedFunction("wasm_alloc"),
			free:             module.ExportedFunction("wasm_free"),
			validateRequest:  module.ExportedFunction("validate_request_v1_wasm"),
			createIdentity:   module.ExportedFunction("create_identity_object_v1_wasm"),
			validateRecovery: module.ExportedFunction("validate_recovery_request_wasm"),
		}

		if err := inst.validate(); err != nil {
			loadErr = err
			_ = module.Close(ctx)
			_ = r.Close(ctx)
			return
		}

		loadedModule = inst
	})

	return loadedModule, loadErr
}

func (i *instance) validate() error {
	missing := []struct {
		name string
		fn   api.Function
	}{
		{"wasm_alloc", i.alloc},
		{"wasm_free", i.free},
		{"validate_request_v1_wasm", i.validateRequest},
		{"create_identity_object_v1_wasm", i.createIdentity},
		{"validate_recovery_request_wasm", i.validateRecovery},
	}

	for _, item := range missing {
		if item.fn == nil {
			return fmt.Errorf("wasm module does not export %s", item.name)
		}
	}
	return nil
}

func wasmPath() string {
	if path := os.Getenv(wasmPathEnv); path != "" {
		return path
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "idiss.wasm"
	}

	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", "idiss", "target", "wasm32-wasip1", "release", "idiss.wasm"))
}
