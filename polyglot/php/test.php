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
    $binding->validate($image);
    if ($binding->contentHashHex($image) !== $entry['content_hash']) {
        throw new RuntimeException($entry['name'] . ': content hash mismatch');
    }
    $canonical = $binding->reencode($image);
    if ($entry['name'] === 'non_canonical') {
        if ($canonical === $image) {
            throw new RuntimeException($entry['name'] . ': expected changed bytes');
        }
    } elseif ($canonical !== $image) {
        throw new RuntimeException($entry['name'] . ': canonical bytes changed');
    }
    $checked++;
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
