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

    static native int hash(byte[] image, byte[] output);

    static native int reencode(byte[] image, byte[] output, int[] outLength);

    static native int redactedJson(byte[] image, byte[] output, int[] outLength);

    static native int fromActive(byte[] source, String name, byte[] output, int[] outLength);
}
