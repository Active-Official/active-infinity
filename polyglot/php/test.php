<?php

declare(strict_types=1);

// PHP conformance test. Run from the repository root:
//   ACTIVE_INFINITY_LIB=/path/libactive_infinity_ffi.so php polyglot/php/test.php

require __DIR__ . '/ActiveInfinity.php';

$root = dirname(__DIR__, 2);
$manifest = json_decode(file_get_contents($root . '/conformance/manifest.json'), true);
$binding = new ActiveInfinity();

// Tripwire: the PHP cdef subset must name only functions the C header declares.
$header = file_get_contents($root . '/ffi/active-infinity-ffi/include/active_infinity.h');
if ($header === false) {
    throw new RuntimeException('cannot read the C header');
}
$source = file_get_contents(__DIR__ . '/ActiveInfinity.php');
if ($source === false) {
    throw new RuntimeException('cannot read the binding');
}
preg_match_all('/\b(active_infinity_[a-z_]+)\s*\(/', $source, $matches);
foreach (array_unique($matches[1]) as $symbol) {
    if (!str_contains($header, $symbol)) {
        throw new RuntimeException("$symbol is missing from active_infinity.h");
    }
}

$checked = 0;
foreach ($manifest['cases'] as $entry) {
    if ($entry['kind'] !== 'valid') {
        continue;
    }
    $image = file_get_contents($root . '/' . $entry['path']);
    if ($entry['name'] === 'non_canonical') {
        // NF-INF02-01: validate and content_hash prove the canonical form
        // (INF-02), so a non-canonical image is refused; reencode is the
        // repair path.
        try {
            $binding->validate($image);
            throw new RuntimeException($entry['name'] . ': non-canonical image was validated');
        } catch (ActiveInfinityError $error) {
            if ($error->errorCode !== 'infinity/not-canonical') {
                throw new RuntimeException($entry['name'] . ': wrong code ' . $error->errorCode);
            }
        }
        try {
            $binding->contentHashHex($image);
            throw new RuntimeException($entry['name'] . ': non-canonical image was hashed');
        } catch (ActiveInfinityError $error) {
            if ($error->errorCode !== 'infinity/not-canonical') {
                throw new RuntimeException($entry['name'] . ': wrong code ' . $error->errorCode);
            }
        }
        // INF-POLY-03: the binding surfaces validateCanonical; it must
        // refuse the non-canonical image with the same code.
        try {
            $binding->validateCanonical($image);
            throw new RuntimeException($entry['name'] . ': non-canonical image passed validateCanonical');
        } catch (ActiveInfinityError $error) {
            if ($error->errorCode !== 'infinity/not-canonical') {
                throw new RuntimeException($entry['name'] . ': wrong code ' . $error->errorCode);
            }
        }
    } else {
        $binding->validate($image);
        $binding->validateCanonical($image);
        if ($binding->contentHashHex($image) !== $entry['content_hash']) {
            throw new RuntimeException($entry['name'] . ': content hash mismatch');
        }
    }
    $canonical = $binding->reencode($image);
    if ($entry['name'] === 'non_canonical') {
        if ($canonical === $image) {
            throw new RuntimeException($entry['name'] . ': expected changed bytes');
        }
        $binding->validate($canonical);
    } elseif ($canonical !== $image) {
        throw new RuntimeException($entry['name'] . ': canonical bytes changed');
    }
    $checked++;
}

// INF-POLY-03: pin the exact count, derived from the manifest -- the test
// used to have no floor at all, so an empty run could PASS.
$valid = count(array_filter($manifest['cases'], fn ($entry) => $entry['kind'] === 'valid'));
if ($checked !== $valid) {
    throw new RuntimeException("valid vectors were not exercised: $checked of $valid");
}

// INF-POLY-02: every invalid vector except the two limits-dependent ones
// (limit, too_deep) must be refused by validateCanonical with exactly the
// manifest's expected_code. The FFI exposes no limits parameter, so those
// two need narrowed limits (max_nodes:1, max_depth:8) and are covered by
// the CLI's `conformance run` and the Rust suite instead. invalid_stream
// vectors are CLI-only: no stream decode exists in the FFI.
$invalidChecked = 0;
$invalidSkipped = 0;
foreach ($manifest['cases'] as $entry) {
    if ($entry['kind'] !== 'invalid') {
        continue;
    }
    if ($entry['name'] === 'limit' || $entry['name'] === 'too_deep') {
        $invalidSkipped++;
        continue;
    }
    $image = file_get_contents($root . '/' . $entry['path']);
    try {
        $binding->validateCanonical($image);
        throw new RuntimeException($entry['name'] . ': invalid image was accepted');
    } catch (ActiveInfinityError $error) {
        if ($error->errorCode !== $entry['expected_code']) {
            throw new RuntimeException($entry['name'] . ': wrong code ' . $error->errorCode);
        }
    }
    $invalidChecked++;
}
$invalidTotal = count(array_filter($manifest['cases'], fn ($entry) => $entry['kind'] === 'invalid'));
if ($invalidChecked + $invalidSkipped !== $invalidTotal) {
    throw new RuntimeException("invalid vectors were not exercised: $invalidChecked + $invalidSkipped of $invalidTotal");
}
if ($invalidSkipped !== 2) {
    throw new RuntimeException("limits-dependent skips changed: $invalidSkipped");
}

$source = "port = 8080\nname = \"php\"\n";
$first = ActiveInfinity::fromActive($source, 'php.active');
$second = ActiveInfinity::fromActive($source, 'php.active');
if ($first !== $second) {
    throw new RuntimeException('Active source encoding is not deterministic');
}
$binding->validate($first);

$full = file_get_contents($root . '/tests/vectors/valid/full.ainf');
$json = $binding->redactedJson($full);
if (str_contains($json, 'CANARY_SECRET_')) {
    throw new RuntimeException('secret canary survived redaction');
}
json_decode($json, true, 512, JSON_THROW_ON_ERROR);

try {
    $binding->validate("\xff\xff");
    throw new RuntimeException('malformed input was accepted');
} catch (ActiveInfinityError $error) {
    if (!str_starts_with($error->errorCode, 'infinity/')) {
        throw new RuntimeException('unstable code ' . $error->errorCode);
    }
}

printf("PHP conformance PASS (%d vectors, ABI %d)\n", $checked, ActiveInfinity::ABI);
