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
int32_t active_infinity_validate(const uint8_t *ptr, size_t len);
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
        $namePointer = FFI::cast('char *', $nameRaw);
        try {
            $size = FFI::new('size_t[1]');
            $size[0] = 0;
            $status = $binding->ffi->active_infinity_from_active(
                $input,
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
                    $input,
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
            if (!is_string($code)) {
                $code = FFI::string($code);
            }
            throw new ActiveInfinityError($code, $status);
        }
    }

    private function checkWithInput(string $image, callable $call): void
    {
        $buffer = $this->buffer($image);
        try {
            $this->check($call($buffer, strlen($image)));
        } finally {
            $this->release($buffer, strlen($image));
        }
    }

    private function buffer(string $bytes): mixed
    {
        if ($bytes === '') {
            return null;
        }
        $pointer = $this->ffi->active_infinity_alloc(strlen($bytes));
        FFI::memcpy($pointer, $bytes, strlen($bytes));
        return $pointer;
    }

    private function release(mixed $pointer, int $length): void
    {
        if ($pointer !== null && $length > 0) {
            $this->ffi->active_infinity_free($pointer, $length);
        }
    }

    private function output(string $image, callable $call): string
    {
        $input = $this->buffer($image);
        try {
            $size = FFI::new('size_t[1]');
            $size[0] = 0;
            $status = $call($input, strlen($image), null, $size);
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
            $this->check($call($input, strlen($image), $out, $size));
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
