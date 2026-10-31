// Package activeinfinity is the Go binding for Active Infinity.
//
// It runs the shared WASM module through wazero, so the reference codec is the
// only canonicalizer and no cgo toolchain is required.
package activeinfinity

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

func fillRandom(buffer []byte) {
	if _, err := rand.Read(buffer); err != nil {
		for index := range buffer {
			buffer[index] = 0
		}
	}
}

// ABI version this binding targets.
const ABI = 1

// Error is a stable infinity/... failure from the reference codec.
type Error struct {
	Code   string
	Status int32
}

func (e *Error) Error() string { return fmt.Sprintf("%s (status %d)", e.Code, e.Status) }

// Instance holds one WASM instance. It is safe for concurrent use.
type Instance struct {
	mu      sync.Mutex
	runtime wazero.Runtime
	module  api.Module
}

// New instantiates the binding from a .wasm file.
func New(ctx context.Context, wasmPath string) (*Instance, error) {
	bytes, err := os.ReadFile(wasmPath)
	if err != nil {
		return nil, err
	}
	runtime := wazero.NewRuntime(ctx)
	var moduleForRandom api.Module
	host, err := runtime.NewHostModuleBuilder("env").
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, ptr, length uint32) uint32 {
			if moduleForRandom == nil {
				return 1
			}
			memory := moduleForRandom.Memory()
			buffer, ok := memory.Read(ptr, length)
			if !ok {
				return 1
			}
			fillRandom(buffer)
			if !memory.Write(ptr, buffer) {
				return 1
			}
			return 0
		}).
		Export("active_random_fill").
		Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	_ = host
	compiled, err := runtime.CompileModule(ctx, bytes)
	if err != nil {
		return nil, err
	}
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig())
	if err != nil {
		return nil, err
	}
	moduleForRandom = module
	abi, err := callU32(ctx, module, "active_infinity_abi_version")
	if err != nil {
		return nil, err
	}
	if abi != ABI {
		return nil, &Error{Code: "infinity/abi-mismatch", Status: -1}
	}
	return &Instance{runtime: runtime, module: module}, nil
}

// Close releases the runtime.
func (i *Instance) Close(ctx context.Context) error { return i.runtime.Close(ctx) }

func callU32(ctx context.Context, module api.Module, name string) (uint32, error) {
	values, err := module.ExportedFunction(name).Call(ctx)
	if err != nil {
		return 0, err
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("export %s returned %d values", name, len(values))
	}
	return uint32(values[0]), nil
}

func (i *Instance) lastError(ctx context.Context) string {
	values, err := i.module.ExportedFunction("active_infinity_last_error").Call(ctx)
	if err != nil || len(values) == 0 {
		return "infinity/unknown"
	}
	pointer := uint32(values[0])
	memory := i.module.Memory()
	end := pointer
	for {
		byteValue, ok := memory.ReadByte(end)
		if !ok || byteValue == 0 {
			break
		}
		end++
	}
	buffer, ok := memory.Read(pointer, end-pointer)
	if !ok {
		return "infinity/unknown"
	}
	return string(buffer)
}

func (i *Instance) check(ctx context.Context, status int32) error {
	if status == 0 {
		return nil
	}
	return &Error{Code: i.lastError(ctx), Status: status}
}

// writeInput copies data into the module and returns the pointer and a release.
func (i *Instance) writeInput(ctx context.Context, data []byte) (uint32, func(), error) {
	alloc := i.module.ExportedFunction("active_infinity_alloc")
	free := i.module.ExportedFunction("active_infinity_free")
	if len(data) == 0 {
		return 0, func() {}, nil
	}
	values, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, nil, err
	}
	pointer := uint32(values[0])
	if !i.module.Memory().Write(pointer, data) {
		return 0, nil, fmt.Errorf("wasm memory write failed")
	}
	return pointer, func() {
		_, _ = free.Call(ctx, uint64(pointer), uint64(len(data)))
	}, nil
}

func (i *Instance) readOutput(ctx context.Context, pointer, length uint32) ([]byte, error) {
	buffer, ok := i.module.Memory().Read(pointer, length)
	if !ok {
		return nil, fmt.Errorf("wasm memory read failed")
	}
	// wazero returns a view into linear memory; copy before the caller frees the
	// block, otherwise the allocator's free-list metadata overwrites the result.
	return append([]byte(nil), buffer...), nil
}

// Validate returns nil for a structurally valid image.
func (i *Instance) Validate(ctx context.Context, image []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	pointer, release, err := i.writeInput(ctx, image)
	if err != nil {
		return err
	}
	defer release()
	values, err := i.module.ExportedFunction("active_infinity_validate").Call(ctx, uint64(pointer), uint64(len(image)))
	if err != nil {
		return err
	}
	return i.check(ctx, int32(uint32(values[0])))
}

// ContentHash returns the 32-byte Blake3 content hash.
func (i *Instance) ContentHash(ctx context.Context, image []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	pointer, release, err := i.writeInput(ctx, image)
	if err != nil {
		return nil, err
	}
	defer release()
	values, err := i.module.ExportedFunction("active_infinity_alloc").Call(ctx, 32)
	if err != nil {
		return nil, err
	}
	hashPointer := uint32(values[0])
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(hashPointer), 32)
	}()
	values, err = i.module.ExportedFunction("active_infinity_content_hash").Call(
		ctx, uint64(pointer), uint64(len(image)), uint64(hashPointer))
	if err != nil {
		return nil, err
	}
	if err := i.check(ctx, int32(uint32(values[0]))); err != nil {
		return nil, err
	}
	return i.readOutput(ctx, hashPointer, 32)
}

// ContentHashHex is ContentHash in lowercase hex.
func (i *Instance) ContentHashHex(ctx context.Context, image []byte) (string, error) {
	hash, err := i.ContentHash(ctx, image)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash), nil
}

func (i *Instance) output(ctx context.Context, name string, prefix []uint64, payload []byte) ([]byte, error) {
	pointer, release, err := i.writeInput(ctx, payload)
	if err != nil {
		return nil, err
	}
	defer release()
	values, err := i.module.ExportedFunction("active_infinity_alloc").Call(ctx, 4)
	if err != nil {
		return nil, err
	}
	lengthPointer := uint32(values[0])
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(lengthPointer), 4)
	}()
	if !i.module.Memory().WriteUint32Le(lengthPointer, 0) {
		return nil, fmt.Errorf("wasm memory write failed")
	}
	call := i.module.ExportedFunction(name)
	args := append([]uint64{uint64(pointer), uint64(len(payload))}, prefix...)
	args = append(args, 0, uint64(lengthPointer))
	values, err = call.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	status := int32(uint32(values[0]))
	required, ok := i.module.Memory().ReadUint32Le(lengthPointer)
	if !ok {
		return nil, fmt.Errorf("wasm memory read failed")
	}
	if status != -2 || required == 0 {
		if err := i.check(ctx, status); err != nil {
			return nil, err
		}
		return []byte{}, nil
	}
	values, err = i.module.ExportedFunction("active_infinity_alloc").Call(ctx, uint64(required))
	if err != nil {
		return nil, err
	}
	outputPointer := uint32(values[0])
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(outputPointer), uint64(required))
	}()
	if !i.module.Memory().WriteUint32Le(lengthPointer, required) {
		return nil, fmt.Errorf("wasm memory write failed")
	}
	args = append([]uint64{uint64(pointer), uint64(len(payload))}, prefix...)
	args = append(args, uint64(outputPointer), uint64(lengthPointer))
	values, err = call.Call(ctx, args...)
	if err != nil {
		return nil, err
	}
	if err := i.check(ctx, int32(uint32(values[0]))); err != nil {
		return nil, err
	}
	written, ok := i.module.Memory().ReadUint32Le(lengthPointer)
	if !ok {
		return nil, fmt.Errorf("wasm memory read failed")
	}
	return i.readOutput(ctx, outputPointer, written)
}

// Reencode returns canonical AINF bytes.
func (i *Instance) Reencode(ctx context.Context, image []byte) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.output(ctx, "active_infinity_reencode", nil, image)
}

// RedactedJSON returns the redacted JSON projection.
func (i *Instance) RedactedJSON(ctx context.Context, image []byte) (string, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	output, err := i.output(ctx, "active_infinity_redacted_json", nil, image)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// FromActive compiles Active text into canonical AINF.
func (i *Instance) FromActive(ctx context.Context, source []byte, name string) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	nameBytes := append([]byte(name), 0)
	namePointer, nameRelease, err := i.writeInput(ctx, nameBytes)
	if err != nil {
		return nil, err
	}
	defer nameRelease()
	return i.output(ctx, "active_infinity_from_active", []uint64{uint64(namePointer)}, source)
}
