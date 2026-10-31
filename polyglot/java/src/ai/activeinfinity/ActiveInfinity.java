package ai.activeinfinity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * Active Infinity for the JVM (Java, Kotlin, Scala).
 *
 * <p>One canonicalizer: validation, content hash, canonical re-encode and
 * redacted JSON call the Rust reference through JNI.
 */
public final class ActiveInfinity {
    public static final int ABI = 1;

    /** A stable {@code infinity/...} failure from the reference codec. */
    public static final class Error extends RuntimeException {
        private final String code;
        private final int status;

        Error(String code, int status) {
            super(code + " (status " + status + ")");
            this.code = code;
            this.status = status;
        }

        public String code() {
            return code;
        }

        public int status() {
            return status;
        }
    }

    private ActiveInfinity() {}

    public static void checkAbi() {
        if (Native.abiVersion() != ABI) {
            throw new Error("infinity/abi-mismatch", -1);
        }
    }

    static void check(int status) {
        if (status != 0) {
            throw new Error(Native.lastError(), status);
        }
    }

    public static void validate(byte[] image) {
        checkAbi();
        check(Native.validate(image));
    }

    public static byte[] contentHash(byte[] image) {
        checkAbi();
        byte[] hash = new byte[32];
        check(Native.hash(image, hash));
        return hash;
    }

    public static String contentHashHex(byte[] image) {
        StringBuilder builder = new StringBuilder(64);
        for (byte value : contentHash(image)) {
            builder.append(String.format("%02x", value));
        }
        return builder.toString();
    }

    public static byte[] reencode(byte[] image) {
        checkAbi();
        int[] length = {0};
        int probe = Native.reencode(image, null, length);
        if (probe != -2) {
            check(probe);
            return new byte[0];
        }
        byte[] output = new byte[length[0]];
        int[] capacity = {output.length};
        check(Native.reencode(image, output, capacity));
        return Arrays.copyOf(output, capacity[0]);
    }

    public static String redactedJson(byte[] image) {
        checkAbi();
        int[] length = {0};
        int probe = Native.redactedJson(image, null, length);
        if (probe != -2) {
            check(probe);
            return "";
        }
        byte[] output = new byte[length[0]];
        int[] capacity = {output.length};
        check(Native.redactedJson(image, output, capacity));
        return new String(output, 0, capacity[0], java.nio.charset.StandardCharsets.UTF_8);
    }

    public static byte[] fromActive(String source, String name) {
        checkAbi();
        byte[] payload = source.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int[] length = {0};
        int probe = Native.fromActive(payload, name, null, length);
        if (probe != -2) {
            check(probe);
            return new byte[0];
        }
        byte[] output = new byte[length[0]];
        int[] capacity = {output.length};
        check(Native.fromActive(payload, name, output, capacity));
        return Arrays.copyOf(output, capacity[0]);
    }

    public static byte[] fromActive(String source) {
        return fromActive(source, "module.active");
    }

    public static byte[] readFile(Path path) throws IOException {
        return Files.readAllBytes(path);
    }
}
