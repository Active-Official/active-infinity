package ai.activeinfinity;

/** Native declarations implemented by {@code libactive_infinity_jni}. */
final class Native {
    static {
        System.loadLibrary("active_infinity_jni");
    }

    private Native() {}

    static native int abiVersion();

    static native String lastError();

    static native int validate(byte[] image);

    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    static native int validateCanonical(byte[] image);

    // INF-FFI-02: caller-supplied budget. The limits are a long[24] in C
    // struct order (see Limits); a null limits means the library defaults.
    static native int limitsDefault(long[] values);

    static native int validateWithLimits(byte[] image, long[] limits);

    static native int decodeWithLimits(byte[] image, long[] limits, byte[] output, int[] outLength);

    static native int hash(byte[] image, byte[] output);

    static native int reencode(byte[] image, byte[] output, int[] outLength);

    static native int redactedJson(byte[] image, byte[] output, int[] outLength);

    static native int fromActive(byte[] source, byte[] name, byte[] output, int[] outLength);
}
