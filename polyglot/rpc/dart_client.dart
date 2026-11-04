// Thin Active RPC client over native ARP1 on TCP (Dart).
//
//   dart run polyglot/rpc/dart_client.dart

import 'dart:convert';
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

const budget = [10000, 67108864, 5000, 100000, 256, 100000, 10000000];

void putString(BytesBuilder builder, String text) {
  final bytes = utf8.encode(text);
  builder.add(_u32(bytes.length));
  builder.add(bytes);
}

Uint8List _u32(int value) {
  final data = ByteData(4);
  data.setUint32(0, value, Endian.little);
  return data.buffer.asUint8List();
}

Uint8List _u64(int value) {
  final data = ByteData(8);
  data.setUint64(0, value, Endian.little);
  return data.buffer.asUint8List();
}

Uint8List request(int id, String method, Uint8List payload, Uint8List? capId) {
  final builder = BytesBuilder();
  builder.add(ascii.encode('ARP1'));
  builder.add([1, 1]);
  builder.add([0, 0]);
  builder.add(_u64(id));
  putString(builder, method);
  builder.add(_u32(0));
  builder.add(_u32(payload.length));
  builder.add(payload);
  if (capId == null) {
    builder.add(_u32(0));
    return builder.toBytes();
  }
  builder.add(_u32(1));
  builder.add(capId);
  builder.add(_u32(1));
  putString(builder, 'echo');
  for (final value in budget) {
    builder.add(_u64(value));
  }
  builder.add([0, 0, 0]);
  return builder.toBytes();
}

/// Read exactly [count] bytes from a socket stream.
///
/// The server sends one frame per connection and may keep the socket open, so
/// waiting for end-of-stream is not an option. Bytes that arrive in the same
/// chunk past [count] stay buffered for the next read.
class _Reader {
  _Reader(this._iterator);

  final StreamIterator<Uint8List> _iterator;
  Uint8List _buffer = Uint8List(0);

  Future<Uint8List> read(int count) async {    while (_buffer.length < count) {
      if (!await _iterator.moveNext()) throw StateError('truncated frame');
      final joined = Uint8List(_buffer.length + _iterator.current.length)
        ..setRange(0, _buffer.length, _buffer)
        ..setRange(_buffer.length, _buffer.length + _iterator.current.length,
            _iterator.current);
      _buffer = joined;
    }
    final head = Uint8List.sublistView(_buffer, 0, count);
    _buffer = Uint8List.sublistView(_buffer, count);
    return head;
  }

  /// Drop the underlying subscription so the isolate can exit.
  Future<void> cancel() => _iterator.cancel();
}

Future<(int, String, Uint8List)> call(String address, Uint8List envelope) async {
  final split = address.lastIndexOf(':');
  final host = address.substring(0, split);
  final port = int.parse(address.substring(split + 1));
  final socket = await Socket.connect(host, port);
  final reader = _Reader(StreamIterator<Uint8List>(socket));
  try {
    final header = ByteData(4)..setUint32(0, envelope.length, Endian.little);
    socket.add(header.buffer.asUint8List());
    socket.add(envelope);
    await socket.flush();
    // Read the length, then exactly that many bytes. A fold() waits for EOF,
    // and the server keeps the connection open for the next frame, so it hung
    // on a persistent server (audit AINF-005).
    final lengthBytes = await reader.read(4);
    final length = ByteData.sublistView(lengthBytes).getUint32(0, Endian.little);
    if (length > 1 << 20) throw StateError('frame exceeds the ceiling');
    final frame = await reader.read(length);
    if (frame.length < 20) throw StateError('short envelope');
    if (ascii.decode(frame.sublist(0, 4)) != 'ARP1' || frame[4] != 1) {
      throw StateError('bad magic');
    }
    final kind = frame[5];
    final methodLength = ByteData.sublistView(frame, 16, 20).getUint32(0, Endian.little);
    if (methodLength > frame.length - 20) throw StateError('truncated method');
    final method = utf8.decode(frame.sublist(20, 20 + methodLength));
    return (kind, method, frame);
  } finally {
    // Drop the read subscription and destroy the socket. `Socket.close()`
    // waits for the subscription and can leave its future pending, and a live
    // subscription keeps the isolate alive: the client printed PASS and never
    // exited (CI 2026-11-04).
    await reader.cancel();
    socket.destroy();
  }
}

Future<void> main() async {
  final address = Platform.environment['ACTIVE_RPC_ADDR'];
  final capHex = Platform.environment['ACTIVE_RPC_CAP'];
  final payloadPath = Platform.environment['ACTIVE_RPC_PAYLOAD'];
  if (address == null || capHex == null || payloadPath == null) {
    stderr.writeln('ACTIVE_RPC_ADDR, ACTIVE_RPC_CAP and ACTIVE_RPC_PAYLOAD are required');
    exit(2);
  }
  final cap = Uint8List.fromList([
    for (var index = 0; index < capHex.length; index += 2)
      int.parse(capHex.substring(index, index + 2), radix: 16),
  ]);
  if (cap.length != 16) throw StateError('ACTIVE_RPC_CAP must be 32 hex characters');
  final payload = File(payloadPath).readAsBytesSync();

  var (kind, method, body) = await call(address, request(42, 'echo', payload, cap));
  final echoed = ByteData.sublistView(body, body.length - 4, body.length).getUint32(0, Endian.little) == 0 &&
      _equal(body.sublist(body.length - 4 - payload.length, body.length - 4), payload);
  if (kind != 2 || ByteData.sublistView(body, 8, 16).getUint64(0, Endian.little) != 42 || !echoed) {
    throw StateError('echo: $kind $method');
  }

  (kind, method, _) = await call(address, request(43, 'refuse', payload, cap));
  if (kind != 3 || method != 'rpc/method-not-granted') {
    throw StateError('refusal: $kind $method');
  }

  (kind, method, _) = await call(address, request(44, 'echo', payload, null));
  if (kind != 3 || method != 'rpc/unknown-capability') {
    throw StateError('missing capability: $kind $method');
  }

  stdout.writeln('Dart thin RPC PASS (echo, refusal, missing capability)');
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var index = 0; index < a.length; index++) {
    if (a[index] != b[index]) return false;
  }
  return true;
}
