/// Active Infinity for Dart (FFI binding over the C ABI).
///
/// One canonicalizer: validation, content hash, canonical re-encode and redacted
/// JSON call the Rust reference through `dart:ffi`.
library active_infinity;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

const int abiVersion = 1;

class ActiveInfinityException implements Exception {
  ActiveInfinityException(this.code, this.status);

  final String code;
  final int status;

  @override
  String toString() => '$code (status $status)';
}

typedef _ValidateNative = Int32 Function(Pointer<Uint8>, IntPtr);
typedef _ValidateDart = int Function(Pointer<Uint8>, int);
typedef _HashNative = Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>);
typedef _HashDart = int Function(Pointer<Uint8>, int, Pointer<Uint8>);
typedef _OutputNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<IntPtr>);
typedef _OutputDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, Pointer<IntPtr>);
typedef _FromActiveNative = Int32 Function(
    Pointer<Uint8>, IntPtr, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);
typedef _FromActiveDart = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, Pointer<Uint8>, Pointer<IntPtr>);
typedef _AllocNative = Pointer<Uint8> Function(IntPtr);
typedef _AllocDart = Pointer<Uint8> Function(int);
typedef _FreeNative = Void Function(Pointer<Uint8>, IntPtr);
typedef _FreeDart = void Function(Pointer<Uint8>, int);
typedef _U32Native = Uint32 Function();
typedef _U32Dart = int Function();
typedef _ErrorNative = Pointer<Uint8> Function();
typedef _ErrorDart = Pointer<Uint8> Function();

class _Native {
  _Native(this.library)
      : validate = library
            .lookupFunction<_ValidateNative, _ValidateDart>(
                'active_infinity_validate'),
        hash = library.lookupFunction<_HashNative, _HashDart>(
            'active_infinity_content_hash'),
        reencode = library.lookupFunction<_OutputNative, _OutputDart>(
            'active_infinity_reencode'),
        redactedJson = library.lookupFunction<_OutputNative, _OutputDart>(
            'active_infinity_redacted_json'),
        fromActive = library
            .lookupFunction<_FromActiveNative, _FromActiveDart>(
                'active_infinity_from_active'),
        alloc = library
            .lookupFunction<_AllocNative, _AllocDart>('active_infinity_alloc'),
        free = library
            .lookupFunction<_FreeNative, _FreeDart>('active_infinity_free'),
        abi = library.lookupFunction<_U32Native, _U32Dart>(
            'active_infinity_abi_version'),
        lastError = library
            .lookupFunction<_ErrorNative, _ErrorDart>('active_infinity_last_error');

  final DynamicLibrary library;
  final _ValidateDart validate;
  final _HashDart hash;
  final _OutputDart reencode;
  final _OutputDart redactedJson;
  final _FromActiveDart fromActive;
  final _AllocDart alloc;
  final _FreeDart free;
  final _U32Dart abi;
  final _ErrorDart lastError;
}

_Native? _nativeCache;

_Native _open() {
  if (_nativeCache != null) return _nativeCache!;
  final configured = Platform.environment['ACTIVE_INFINITY_LIB'];
  DynamicLibrary library;
  if (configured != null && configured.isNotEmpty) {
    library = DynamicLibrary.open(configured);
  } else if (Platform.isWindows) {
    library = DynamicLibrary.open('active_infinity_ffi.dll');
  } else if (Platform.isMacOS) {
    library = DynamicLibrary.open('libactive_infinity_ffi.dylib');
  } else {
    library = DynamicLibrary.open('libactive_infinity_ffi.so');
  }
  final native = _Native(library);
  final abi = native.abi();
  if (abi != abiVersion) {
    throw ActiveInfinityException('infinity/abi-mismatch', -1);
  }
  _nativeCache = native;
  return native;
}

String _lastError(_Native native) {
  var pointer = native.lastError();
  final bytes = <int>[];
  while (pointer.address != 0 && pointer.value != 0) {
    bytes.add(pointer.value);
    pointer = pointer.elementAt(1);
  }
  return utf8.decode(bytes);
}

class Image {
  Image(this.bytes);

  final Uint8List bytes;

  factory Image.fromFile(String path) => Image(File(path).readAsBytesSync());

  Image validate() {
    final native = _open();
    _withInput(bytes, (pointer, length) {
      final status = native.validate(pointer, length);
      if (status != 0) {
        throw ActiveInfinityException(_lastError(native), status);
      }
    });
    return this;
  }

  Uint8List contentHash() {
    final native = _open();
    final out = native.alloc(32);
    try {
      _withInput(bytes, (pointer, length) {
        final status = native.hash(pointer, length, out);
        if (status != 0) {
          throw ActiveInfinityException(_lastError(native), status);
        }
      });
      return Uint8List.fromList(out.asTypedList(32));
    } finally {
      native.free(out, 32);
    }
  }

  String contentHashHex() => contentHash()
      .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
      .join();

  Uint8List reencode() => _output(bytes, (native, input, length, out, size) =>
      native.reencode(input, length, out, size));

  String redactedJson() => utf8.decode(
      _output(bytes, (native, input, length, out, size) =>
          native.redactedJson(input, length, out, size)));

  static Uint8List fromActive(String source, {String name = 'module.active'}) {
    final native = _open();
    final payload = Uint8List.fromList(utf8.encode(source));
    final nameBytes = Uint8List.fromList(utf8.encode('$name\u0000'));
    final namePointer = native.alloc(nameBytes.length);
    namePointer.asTypedList(nameBytes.length).setAll(0, nameBytes);
    try {
      return _output(payload, (native, input, length, out, size) =>
          native.fromActive(input, length, namePointer, out, size));
    } finally {
      native.free(namePointer, nameBytes.length);
    }
  }
}

void _withInput(Uint8List payload, void Function(Pointer<Uint8>, int) action) {
  final native = _open();
  if (payload.isEmpty) {
    action(Pointer<Uint8>.fromAddress(0), 0);
    return;
  }
  final pointer = native.alloc(payload.length);
  pointer.asTypedList(payload.length).setAll(0, payload);
  try {
    action(pointer, payload.length);
  } finally {
    native.free(pointer, payload.length);
  }
}

typedef _OutputInvoker = int Function(
    _Native native, Pointer<Uint8> input, int length, Pointer<Uint8> out,
    Pointer<IntPtr> size);

Uint8List _output(Uint8List payload, _OutputInvoker invoke) {
  final native = _open();
  late Uint8List result;
  _withInput(payload, (pointer, length) {
    final lengthPointer = _allocateSize(native);
    try {
      lengthPointer.value = 0;
      var status = invoke(native, pointer, length, Pointer<Uint8>.fromAddress(0), lengthPointer);
      if (status != -2) {
        if (status != 0) {
          throw ActiveInfinityException(_lastError(native), status);
        }
        result = Uint8List(0);
        return;
      }
      final required = lengthPointer.value;
      if (required == 0) {
        result = Uint8List(0);
        return;
      }
      final out = native.alloc(required);
      try {
        lengthPointer.value = required;
        status = invoke(native, pointer, length, out, lengthPointer);
        if (status != 0) {
          throw ActiveInfinityException(_lastError(native), status);
        }
        result = Uint8List.fromList(out.asTypedList(lengthPointer.value));
      } finally {
        native.free(out, required);
      }
    } finally {
      _freeSize(native, lengthPointer);
    }
  });
  return result;
}

Pointer<IntPtr> _allocateSize(_Native native) {
  // `size_t` is `IntPtr`-sized; the C ABI only needs 4 or 8 bytes.
  final pointer = native.alloc(sizeOf<IntPtr>()).cast<IntPtr>();
  return pointer;
}

void _freeSize(_Native native, Pointer<IntPtr> pointer) {
  native.free(pointer.cast<Uint8>(), sizeOf<IntPtr>());
}
