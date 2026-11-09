/// Dart conformance test. Run from the repository root:
///   dart run polyglot/dart/bin/conformance.dart
library;

import 'dart:convert';
import 'dart:ffi';
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
    if (entry['name'] == 'non_canonical') {
      // NF-INF02-01: validate and content_hash prove the canonical form
      // (INF-02), so a non-canonical image is refused; reencode is the
      // repair path.
      try {
        image.validate();
        throw StateError('${entry['name']}: non-canonical image was validated');
      } on ActiveInfinityException catch (error) {
        if (error.code != 'infinity/not-canonical') rethrow;
      }
      try {
        image.contentHashHex();
        throw StateError('${entry['name']}: non-canonical image was hashed');
      } on ActiveInfinityException catch (error) {
        if (error.code != 'infinity/not-canonical') rethrow;
      }
      // INF-POLY-03: the binding surfaces validateCanonical; it must refuse
      // the non-canonical image with the same code.
      try {
        image.validateCanonical();
        throw StateError('${entry['name']}: non-canonical image passed validateCanonical');
      } on ActiveInfinityException catch (error) {
        if (error.code != 'infinity/not-canonical') rethrow;
      }
    } else {
      image.validate();
      image.validateCanonical();
      if (image.contentHashHex() != entry['content_hash']) {
        throw StateError('${entry['name']}: content hash mismatch');
      }
    }
    final canonical = image.reencode();
    if (entry['name'] == 'non_canonical') {
      if (String.fromCharCodes(canonical) == String.fromCharCodes(image.bytes)) {
        throw StateError('${entry['name']}: expected changed bytes');
      }
      Image(canonical).validate();
    } else if (!_equal(canonical, image.bytes)) {
      throw StateError('${entry['name']}: canonical bytes changed');
    }
    checked++;
  }

  // INF-POLY-03: pin the exact count, derived from the manifest -- the test
  // used to have no floor at all, so an empty run could PASS.
  final valid = cases.where((entry) => entry['kind'] == 'valid').length;
  if (checked != valid) {
    throw StateError('valid vectors were not exercised: $checked of $valid');
  }

  // INF-POLY-02: every invalid vector must be refused with exactly the
  // manifest's expected_code. INF-FFI-02: the two limits-dependent ones
  // (limit, too_deep) go through validateWithLimits with the narrowed budget
  // from the entry's options.limits (max_nodes:1, max_depth:8); the rest go
  // through validateCanonical. invalid_stream vectors are CLI-only: no stream
  // decode exists in the FFI.
  var invalidChecked = 0;
  for (final entry in cases) {
    if (entry['kind'] != 'invalid') continue;
    final image = Image.fromFile('$root/${entry['path']}');
    final limitsSpec =
        (entry['options'] as Map?)?['limits'] as String?;
    if (limitsSpec != null) {
      final parts = limitsSpec.split(':');
      final limits = Limits.defaults();
      try {
        limits.ref.setField(parts[0], int.parse(parts[1]));
        try {
          image.validateWithLimits(limits);
          throw StateError('${entry['name']}: invalid image was accepted');
        } on ActiveInfinityException catch (error) {
          if (error.code != entry['expected_code']) {
            throw StateError('${entry['name']}: wrong code ${error.code}');
          }
        }
      } finally {
        calloc.free(limits);
      }
    } else {
      try {
        image.validateCanonical();
        throw StateError('${entry['name']}: invalid image was accepted');
      } on ActiveInfinityException catch (error) {
        if (error.code != entry['expected_code']) {
          throw StateError('${entry['name']}: wrong code ${error.code}');
        }
      }
    }
    invalidChecked++;
  }
  final invalidTotal = cases.where((entry) => entry['kind'] == 'invalid').length;
  if (invalidChecked != invalidTotal) {
    throw StateError('invalid vectors were not exercised: $invalidChecked of $invalidTotal');
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
