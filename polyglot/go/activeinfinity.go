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

// fillRandom fills the buffer or reports failure. A zero-filled buffer would
// be predictable key material, so the host function must fail closed instead.
func fillRandom(buffer []byte) error {
	if _, err := rand.Read(buffer); err != nil {
		return err
	}
	return nil
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
	// Every error path below must close the runtime; wazero holds OS resources.
	ok := false
	defer func() {
		if !ok {
			_ = runtime.Close(ctx)
		}
	}()
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
			if err := fillRandom(buffer); err != nil {
				return 1
			}
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
	ok = true
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
	if pointer == 0 {
		// A null error pointer means "unavailable", not address zero.
		return "infinity/unknown"
	}
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

// alloc allocates in the module and refuses a null pointer. The FFI caps one
// allocation at 1 GiB, so a larger input must fail closed before any write.
func (i *Instance) alloc(ctx context.Context, length uint64) (uint32, error) {
	values, err := i.module.ExportedFunction("active_infinity_alloc").Call(ctx, length)
	if err != nil {
		return 0, err
	}
	pointer := uint32(values[0])
	if pointer == 0 && length > 0 {
		return 0, &Error{Code: "infinity/limit", Status: -1}
	}
	return pointer, nil
}

// writeInput copies data into the module and returns the pointer and a release.
func (i *Instance) writeInput(ctx context.Context, data []byte) (uint32, func(), error) {
	free := i.module.ExportedFunction("active_infinity_free")
	if len(data) == 0 {
		return 0, func() {}, nil
	}
	pointer, err := i.alloc(ctx, uint64(len(data)))
	if err != nil {
		return 0, nil, err
	}
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

// Limits is a caller-supplied budget (INF-FFI-02): one ceiling per
// field, in the same order as the C `active_infinity_limits` struct.
type Limits struct {
	MaxNodes        uint32
	MaxEdges        uint32
	MaxChildren     uint32
	MaxFields       uint32
	MaxParts        uint32
	MaxStrings      uint32
	MaxStringBytes  uint32
	MaxBlobs        uint32
	MaxBlobBytes    uint32
	MaxAnnotations  uint32
	MaxUnits        uint32
	MaxTypes        uint32
	MaxAux          uint32
	MaxNumbers      uint32
	MaxSecrets      uint32
	MaxSecretBytes  uint32
	MaxExtensions   uint32
	MaxProvBytes    uint32
	MaxProvEntries  uint32
	MaxHashes       uint32
	MaxBindings     uint32
	MaxTotalBytes   uint64
	MaxDecodedBytes uint64
	MaxDepth        uint32
}

// limitsSize is the C struct size in bytes (112): 21 uint32 ceilings, 4
// bytes padding, max_total_bytes and max_decoded_bytes (uint64), then
// max_depth (uint32), 4 bytes trailing padding.
const limitsSize = 112

// limitsOffsets is each ceiling's byte offset in the struct, in order.
// limitsWide marks the two uint64 ceilings.
var limitsOffsets = []uint32{
	0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80,
	88, 96, 104,
}

var limitsWide = []bool{
	false, false, false, false, false, false, false, false, false, false,
	false, false, false, false, false, false, false, false, false, false,
	false, true, true, false,
}

// values returns the 24 ceilings in struct order.
func (l Limits) values() []uint64 {
	return []uint64{
		uint64(l.MaxNodes), uint64(l.MaxEdges), uint64(l.MaxChildren),
		uint64(l.MaxFields), uint64(l.MaxParts), uint64(l.MaxStrings),
		uint64(l.MaxStringBytes), uint64(l.MaxBlobs), uint64(l.MaxBlobBytes),
		uint64(l.MaxAnnotations), uint64(l.MaxUnits), uint64(l.MaxTypes),
		uint64(l.MaxAux), uint64(l.MaxNumbers), uint64(l.MaxSecrets),
		uint64(l.MaxSecretBytes), uint64(l.MaxExtensions), uint64(l.MaxProvBytes),
		uint64(l.MaxProvEntries), uint64(l.MaxHashes), uint64(l.MaxBindings),
		l.MaxTotalBytes, l.MaxDecodedBytes, uint64(l.MaxDepth),
	}
}

func limitsFromValues(values []uint64) Limits {
	return Limits{
		MaxNodes: uint32(values[0]), MaxEdges: uint32(values[1]),
		MaxChildren: uint32(values[2]), MaxFields: uint32(values[3]),
		MaxParts: uint32(values[4]), MaxStrings: uint32(values[5]),
		MaxStringBytes: uint32(values[6]), MaxBlobs: uint32(values[7]),
		MaxBlobBytes: uint32(values[8]), MaxAnnotations: uint32(values[9]),
		MaxUnits: uint32(values[10]), MaxTypes: uint32(values[11]),
		MaxAux: uint32(values[12]), MaxNumbers: uint32(values[13]),
		MaxSecrets: uint32(values[14]), MaxSecretBytes: uint32(values[15]),
		MaxExtensions: uint32(values[16]), MaxProvBytes: uint32(values[17]),
		MaxProvEntries: uint32(values[18]), MaxHashes: uint32(values[19]),
		MaxBindings: uint32(values[20]), MaxTotalBytes: values[21],
		MaxDecodedBytes: values[22], MaxDepth: uint32(values[23]),
	}
}

// SetField sets one ceiling by its C field name (e.g. `max_nodes`). It
// fails closed on an unknown name.
func (l *Limits) SetField(name string, value uint64) error {
	switch name {
	case "max_nodes":
		l.MaxNodes = uint32(value)
	case "max_edges":
		l.MaxEdges = uint32(value)
	case "max_children":
		l.MaxChildren = uint32(value)
	case "max_fields":
		l.MaxFields = uint32(value)
	case "max_parts":
		l.MaxParts = uint32(value)
	case "max_strings":
		l.MaxStrings = uint32(value)
	case "max_string_bytes":
		l.MaxStringBytes = uint32(value)
	case "max_blobs":
		l.MaxBlobs = uint32(value)
	case "max_blob_bytes":
		l.MaxBlobBytes = uint32(value)
	case "max_annotations":
		l.MaxAnnotations = uint32(value)
	case "max_units":
		l.MaxUnits = uint32(value)
	case "max_types":
		l.MaxTypes = uint32(value)
	case "max_aux":
		l.MaxAux = uint32(value)
	case "max_numbers":
		l.MaxNumbers = uint32(value)
	case "max_secrets":
		l.MaxSecrets = uint32(value)
	case "max_secret_bytes":
		l.MaxSecretBytes = uint32(value)
	case "max_extensions":
		l.MaxExtensions = uint32(value)
	case "max_prov_bytes":
		l.MaxProvBytes = uint32(value)
	case "max_prov_entries":
		l.MaxProvEntries = uint32(value)
	case "max_hashes":
		l.MaxHashes = uint32(value)
	case "max_bindings":
		l.MaxBindings = uint32(value)
	case "max_total_bytes":
		l.MaxTotalBytes = value
	case "max_decoded_bytes":
		l.MaxDecodedBytes = value
	case "max_depth":
		l.MaxDepth = uint32(value)
	default:
		return fmt.Errorf("unknown limits field %s", name)
	}
	return nil
}

// writeLimits copies a Limits into WASM memory and returns the pointer and
// a release. A nil limits means the library defaults (a null pointer).
func (i *Instance) writeLimits(ctx context.Context, limits *Limits) (uint32, func(), error) {
	free := i.module.ExportedFunction("active_infinity_free")
	if limits == nil {
		return 0, func() {}, nil
	}
	pointer, err := i.alloc(ctx, limitsSize)
	if err != nil {
		return 0, nil, err
	}
	memory := i.module.Memory()
	for index, value := range limits.values() {
		if limitsWide[index] {
			if !memory.WriteUint64Le(pointer+limitsOffsets[index], value) {
				return 0, nil, fmt.Errorf("wasm memory write failed")
			}
		} else if !memory.WriteUint32Le(pointer+limitsOffsets[index], uint32(value)) {
			return 0, nil, fmt.Errorf("wasm memory write failed")
		}
	}
	return pointer, func() {
		_, _ = free.Call(ctx, uint64(pointer), uint64(limitsSize))
	}, nil
}

// DefaultLimits fills a Limits with the library defaults (via the FFI).
func (i *Instance) DefaultLimits(ctx context.Context) (Limits, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	pointer, err := i.alloc(ctx, limitsSize)
	if err != nil {
		return Limits{}, err
	}
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(pointer), uint64(limitsSize))
	}()
	values, err := i.module.ExportedFunction("active_infinity_limits_default").Call(ctx, uint64(pointer))
	if err != nil {
		return Limits{}, err
	}
	if err := i.check(ctx, int32(uint32(values[0]))); err != nil {
		return Limits{}, err
	}
	memory := i.module.Memory()
	read := make([]uint64, len(limitsOffsets))
	for index := range limitsOffsets {
		if limitsWide[index] {
			value, ok := memory.ReadUint64Le(pointer + limitsOffsets[index])
			if !ok {
				return Limits{}, fmt.Errorf("wasm memory read failed")
			}
			read[index] = value
		} else {
			value, ok := memory.ReadUint32Le(pointer + limitsOffsets[index])
			if !ok {
				return Limits{}, fmt.Errorf("wasm memory read failed")
			}
			read[index] = uint64(value)
		}
	}
	return limitsFromValues(read), nil
}

// ValidateCanonical proves the image is the canonical encoding of its
// own content. Validate already proves this (INF-02); this states the
// requirement explicitly. (INF-POLY-03)
func (i *Instance) ValidateCanonical(ctx context.Context, image []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	pointer, release, err := i.writeInput(ctx, image)
	if err != nil {
		return err
	}
	defer release()
	values, err := i.module.ExportedFunction("active_infinity_validate_canonical").Call(ctx, uint64(pointer), uint64(len(image)))
	if err != nil {
		return err
	}
	return i.check(ctx, int32(uint32(values[0])))
}

// ValidateWithLimits is the limits-parameterized form of
// ValidateCanonical. A nil limits means the library defaults. (INF-FFI-02)
func (i *Instance) ValidateWithLimits(ctx context.Context, image []byte, limits *Limits) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	pointer, release, err := i.writeInput(ctx, image)
	if err != nil {
		return err
	}
	defer release()
	limitsPointer, limitsRelease, err := i.writeLimits(ctx, limits)
	if err != nil {
		return err
	}
	defer limitsRelease()
	values, err := i.module.ExportedFunction("active_infinity_validate_with_limits").Call(ctx, uint64(pointer), uint64(len(image)), uint64(limitsPointer))
	if err != nil {
		return err
	}
	return i.check(ctx, int32(uint32(values[0])))
}

// DecodeWithLimits is the limits-parameterized form of Reencode. A nil
// limits means the library defaults. (INF-FFI-02)
func (i *Instance) DecodeWithLimits(ctx context.Context, image []byte, limits *Limits) ([]byte, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	limitsPointer, limitsRelease, err := i.writeLimits(ctx, limits)
	if err != nil {
		return nil, err
	}
	defer limitsRelease()
	return i.output(ctx, "active_infinity_decode_with_limits", []uint64{uint64(limitsPointer)}, image)
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
	hashPointer, err := i.alloc(ctx, 32)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(hashPointer), 32)
	}()
	values, err := i.module.ExportedFunction("active_infinity_content_hash").Call(
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
	lengthPointer, err := i.alloc(ctx, 4)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = i.module.ExportedFunction("active_infinity_free").Call(ctx, uint64(lengthPointer), 4)
	}()
	if !i.module.Memory().WriteUint32Le(lengthPointer, 0) {
		return nil, fmt.Errorf("wasm memory write failed")
	}
	call := i.module.ExportedFunction(name)
	args := append([]uint64{uint64(pointer), uint64(len(payload))}, prefix...)
	args = append(args, 0, uint64(lengthPointer))
	values, err := call.Call(ctx, args...)
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
	outputPointer, err := i.alloc(ctx, uint64(required))
	if err != nil {
		return nil, err
	}
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
