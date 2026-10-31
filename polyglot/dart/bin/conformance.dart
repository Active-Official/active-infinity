/// Dart conformance test. Run from the repository root:
///   dart run polyglot/dart/bin/conformance.dart
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../lib/active_infinity.dart';

void main() {
  final root = Directory.current.path;
  final manifest = jsonDecode(
      File('$root/conformance/manifest.json').readAsStringSync()) as Map<String, dynamic>;
  final cases = (manifest['cases'] as List).cast<Map<String, dynamic>>();

  var checked = 0;
  for (final entry in cases) {
    if (entry['kind'] != 'valid') continue;
    final image = Image.fromFile('$root/${entry['path']}');
    image.validate();
    if (image.contentHashHex() != entry['content_hash']) {
      throw StateError('${entry['name']}: content hash mismatch');
    }
    final canonical = image.reencode();
    if (entry['name'] == 'non_canonical') {
      if (String.fromCharCodes(canonical) == String.fromCharCodes(image.bytes)) {
        throw StateError('${entry['name']}: expected changed bytes');
      }
    } else if (!_equal(canonical, image.bytes)) {
      throw StateError('${entry['name']}: canonical bytes changed');
    }
    checked++;
  }

  const source = 'port = 8080\nname = "dart"\n';
  final first = Image.fromActive(source, name: 'dart.active');
  final second = Image.fromActive(source, name: 'dart.active');
  if (!_equal(first, second)) {
    throw StateError('Active source encoding is not deterministic');
  }
  Image(first).validate();

  final full = Image.fromFile('$root/tests/vectors/valid/full.ainf');
  final redacted = full.redactedJson();
  if (redacted.contains('CANARY_SECRET_')) {
    throw StateError('secret canary survived redaction');
  }
  jsonDecode(redacted);

  try {
    Image(Uint8List.fromList([0xff, 0xff])).validate();
    throw StateError('malformed input was accepted');
  } on ActiveInfinityException catch (error) {
    if (!error.code.startsWith('infinity/')) {
      throw StateError('unstable code ${error.code}');
    }
  }

  print('Dart conformance PASS ($checked vectors, ABI $abiVersion)');
}

bool _equal(List<int> first, List<int> second) {
  if (first.length != second.length) return false;
  for (var index = 0; index < first.length; index++) {
    if (first[index] != second[index]) return false;
  }
  return true;
}
