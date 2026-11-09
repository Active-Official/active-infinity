<?php

declare(strict_types=1);

/**
 * Active Infinity for PHP (FFI binding over the C ABI).
 *
 * Enable ext-ffi (default in CLI builds) and point ACTIVE_INFINITY_LIB at the
 * shared library. See polyglot/php/test.php for a conformance run.
 */
final class ActiveInfinity
{
    public const ABI = 1;

    /**
     * The declarations PHP's FFI parser accepts. It does not preprocess the C
     * header (no #ifdef, no extern "C"), so the subset is kept here; `test.php`
     * asserts that every name below exists in `include/active_infinity.h`.
     */
    private const CDEF = <<<'C'
uint32_t active_infinity_abi_version(void);
const char *active_infinity_version(void);
const char *active_infinity_last_error(void);
uint8_t *active_infinity_alloc(size_t len);
void active_infinity_free(uint8_t *ptr, size_t len);
uint8_t *active_infinity_alloc_gen(size_t len, uint64_t *generation_out);
int32_t active_infinity_free_gen(uint8_t *ptr, size_t len, uint64_t generation);
int32_t active_infinity_validate(const uint8_t *ptr, size_t len);
int32_t active_infinity_validate_canonical(const uint8_t *ptr, size_t len);
typedef struct {
    uint32_t max_nodes;
    uint32_t max_edges;
    uint32_t max_children;
    uint32_t max_fields;
    uint32_t max_parts;
    uint32_t max_strings;
    uint32_t max_string_bytes;
    uint32_t max_blobs;
    uint32_t max_blob_bytes;
    uint32_t max_annotations;
    uint32_t max_units;
    uint32_t max_types;
    uint32_t max_aux;
    uint32_t max_numbers;
    uint32_t max_secrets;
    uint32_t max_secret_bytes;
    uint32_t max_extensions;
    uint32_t max_prov_bytes;
    uint32_t max_prov_entries;
    uint32_t max_hashes;
    uint32_t max_bindings;
    uint64_t max_total_bytes;
    uint64_t max_decoded_bytes;
    uint32_t max_depth;
} active_infinity_limits;
int32_t active_infinity_limits_default(active_infinity_limits *limits);
int32_t active_infinity_validate_with_limits(const uint8_t *ptr, size_t len, const active_infinity_limits *limits);
int32_t active_infinity_decode_with_limits(const uint8_t *ptr, size_t len, const active_infinity_limits *limits, uint8_t *out, size_t *out_len);
int32_t active_infinity_content_hash(const uint8_t *ptr, size_t len, uint8_t *out32);
int32_t active_infinity_reencode(const uint8_t *ptr, size_t len, uint8_t *out, size_t *out_len);
int32_t active_infinity_from_active(const uint8_t *source, size_t source_len, const char *name, uint8_t *out, size_t *out_len);
int32_t active_infinity_redacted_json(const uint8_t *ptr, size_t len, uint8_t *out, size_t *out_len);
C;

    private FFI $ffi;

    public function __construct(?string $library = null)
    {
        if (!extension_loaded('ffi')) {
            throw new RuntimeException('ext-ffi is not enabled');
        }
        $resolved = $library ?? getenv('ACTIVE_INFINITY_LIB');
        if ($resolved === false || $resolved === '') {
            $resolved = 'active_infinity_ffi';
        }
        $this->ffi = FFI::cdef(self::CDEF, $resolved);
        if ($this->ffi->active_infinity_abi_version() !== self::ABI) {
            throw new ActiveInfinityError('infinity/abi-mismatch', -1);
        }
    }

    public function validate(string $image): void
    {
        $this->checkWithInput($image, fn ($pointer, int $length) =>
            $this->ffi->active_infinity_validate($pointer, $length));
    }

    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    public function validateCanonical(string $image): void
    {
        $this->checkWithInput($image, fn ($pointer, int $length) =>
            $this->ffi->active_infinity_validate_canonical($pointer, $length));
    }

    // INF-FFI-02: caller-supplied budget. Returns a Limits struct filled
    // with the library defaults; override the ceiling to tighten.
    public function limitsDefault(): FFI\CData
    {
        // NF-FFI01-01: the static FFI::new() cannot resolve a CDEF-defined
        // type (it only knows builtin types), so limitsDefault() threw
        // "Undefined C type active_infinity_limits" on every call. The
        // type must be allocated through the FFI instance that loaded the
        // CDEF.
        $limits = $this->ffi->new('active_infinity_limits');
        $this->check($this->ffi->active_infinity_limits_default(FFI::addr($limits)));
        return $limits;
    }

    // INF-FFI-02: the limits-parameterized form of validateCanonical.
    // null means the library defaults.
    public function validateWithLimits(string $image, ?FFI\CData $limits = null): void
    {
        $pointer = $limits === null ? null : FFI::addr($limits);
        $this->checkWithInput($image, fn ($buffer, int $length) =>
            $this->ffi->active_infinity_validate_with_limits($buffer, $length, $pointer));
    }

    // INF-FFI-02: the limits-parameterized form of reencode. A null limits
    // is materialized through limitsDefault() so the FFI always receives a
    // struct pointer.
    public function decodeWithLimits(string $image, ?FFI\CData $limits = null): string
    {
        $limits = $limits ?? $this->limitsDefault();
        $input = $this->buffer($image);
        try {
            $size = FFI::new('size_t[1]');
            $size[0] = 0;
            $status = $this->ffi->active_infinity_decode_with_limits(
                $input[0], strlen($image), FFI::addr($limits), null, $size
            );
            if ($status !== -2) {
                $this->check($status);
                return '';
            }
            $required = (int) $size[0];
            if ($required === 0) {
                return '';
            }
            $out = FFI::new("uint8_t[$required]");
            $size[0] = $required;
            $this->check($this->ffi->active_infinity_decode_with_limits(
                $input[0], strlen($image), FFI::addr($limits), $out, $size
            ));
            return FFI::string($out, (int) $size[0]);
        } finally {
            $this->release($input, strlen($image));
        }
    }

    public function contentHash(string $image): string
    {
        $out = FFI::new('uint8_t[32]');
        $this->checkWithInput($image, function ($pointer, int $length) use ($out) {
            return $this->ffi->active_infinity_content_hash($pointer, $length, $out);
        });
        return FFI::string($out, 32);
    }

    public function contentHashHex(string $image): string
    {
        return bin2hex($this->contentHash($image));
    }

    public function reencode(string $image): string
    {
        return $this->output($image, fn ($input, int $length, $output, $size) =>
            $this->ffi->active_infinity_reencode($input, $length, $output, $size));
    }

    public function redactedJson(string $image): string
    {
        return $this->output($image, fn ($input, int $length, $output, $size) =>
            $this->ffi->active_infinity_redacted_json($input, $length, $output, $size));
    }

    public static function fromActive(string $source, string $name = 'module.active'): string
    {
        $binding = new self();
        $nameBytes = $name . "\0";
        $input = $binding->buffer($source);
        $nameRaw = $binding->buffer($nameBytes);
        $namePointer = FFI::cast('char *', $nameRaw[0]);
        try {
            $size = FFI::new('size_t[1]');
            $size[0] = 0;
            $status = $binding->ffi->active_infinity_from_active(
                $input[0],
                strlen($source),
                $namePointer,
                null,
                $size
            );
            if ($status !== -2) {
                $binding->check($status);
                return '';
            }
            $required = (int) $size[0];
            if ($required === 0) {
                return '';
            }
            $out = FFI::new("uint8_t[$required]");
            $size[0] = $required;
            $binding->check(
                $binding->ffi->active_infinity_from_active(
                    $input[0],
                    strlen($source),
                    $namePointer,
                    $out,
                    $size
                )
            );
            return FFI::string($out, (int) $size[0]);
        } finally {
            $binding->release($input, strlen($source));
            $binding->release($nameRaw, strlen($nameBytes));
        }
    }

    private function check(int $status): void
    {
        if ($status !== 0) {
            $code = $this->ffi->active_infinity_last_error();
            if ($code === null) {
                $code = 'infinity/unknown';
            } elseif (!is_string($code)) {
                $code = FFI::string($code);
            }
            throw new ActiveInfinityError($code, $status);
        }
    }

    private function checkWithInput(string $image, callable $call): void
    {
        $buffer = $this->buffer($image);
        try {
            $this->check($call($buffer[0], strlen($image)));
        } finally {
            $this->release($buffer, strlen($image));
        }
    }

    // INF-FFI-01: allocates generationally and returns the pointer with
    // the generation the FFI handed out with it, as [pointer, generation].
    // An empty input has no allocation: [null, 0]. The generation
    // out-pointer is an FFI::new('uint64_t[1]') (not an FFI allocation), so
    // the legacy pair is not involved. A refused free_gen (stale handle) is
    // a binding bug; it is ignored in `release` rather than thrown from a
    // `finally`, where it would mask the operation's own error.
    private function buffer(string $bytes): array
    {
        if ($bytes === '') {
            return [null, 0];
        }
        $generationOut = FFI::new('uint64_t[1]');
        $pointer = $this->ffi->active_infinity_alloc_gen(strlen($bytes), $generationOut);
        // A null pointer means the FFI refused the allocation (1 GiB cap).
        if ($pointer === null) {
            throw new ActiveInfinityError('infinity/limit', -1);
        }
        FFI::memcpy($pointer, $bytes, strlen($bytes));
        return [$pointer, (int) $generationOut[0]];
    }

    private function release(array $buffer, int $length): void
    {
        if ($buffer[0] !== null && $length > 0) {
            $this->ffi->active_infinity_free_gen($buffer[0], $length, $buffer[1]);
        }
    }

    private function output(string $image, callable $call): string
    {
        $input = $this->buffer($image);
        try {
            $size = FFI::new('size_t[1]');
            $size[0] = 0;
            $status = $call($input[0], strlen($image), null, $size);
            if ($status !== -2) {
                $this->check($status);
                return '';
            }
            $required = (int) $size[0];
            if ($required === 0) {
                return '';
            }
            $out = FFI::new("uint8_t[$required]");
            $size[0] = $required;
            $this->check($call($input[0], strlen($image), $out, $size));
            return FFI::string($out, (int) $size[0]);
        } finally {
            $this->release($input, strlen($image));
        }
    }
}

final class ActiveInfinityError extends RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly int $status)
    {
        parent::__construct(sprintf('%s (status %d)', $errorCode, $status));
    }
}
