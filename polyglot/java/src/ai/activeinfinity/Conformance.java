package ai.activeinfinity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** JVM conformance runner over the shared manifest. */
public final class Conformance {
    private static final Pattern CASE = Pattern.compile(
            "\"path\"\\s*:\\s*\"([^\"]+)\".*?\"content_hash\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.DOTALL);

    // INF-FFI-02: the limits option. It captures the `limits` value
    // (e.g. `max_nodes:1`) from the options object the invalid-case
    // pattern captures.
    private static final Pattern LIMITS_OPTION = Pattern.compile(
            "\"limits\"\\s*:\\s*\"([^\"]+)\"");

    // INF-POLY-02: the invalid-case pattern. It anchors on
    // `"kind": "invalid"` with the closing quote, so it never matches
    // `"kind": "invalid_stream"`; the `.*?` spans the options object,
    // which sits between path and expected_code and never contains an
    // expected_code of its own.
    private static final Pattern INVALID_CASE = Pattern.compile(
            "\"kind\"\\s*:\\s*\"invalid\".*?\"name\"\\s*:\\s*\"([^\"]+)\".*?\"path\"\\s*:\\s*\"([^\"]+)\".*?\"options\"\\s*:\\s*\\{([^}]*)\\}.*?\"expected_code\"\\s*:\\s*\"([^\"]+)\"",
            Pattern.DOTALL);

    public static void main(String[] args) throws IOException {
        Path root = Paths.get("").toAbsolutePath();
        String manifest = Files.readString(root.resolve("conformance/manifest.json"));

        int checked = 0;
        Matcher matcher = CASE.matcher(manifest);
        while (matcher.find()) {
            String path = matcher.group(1);
            String expected = matcher.group(2);
            if (!path.contains("/valid/")) {
                continue;
            }
            byte[] image = Files.readAllBytes(root.resolve(path));
            if (path.contains("non_canonical")) {
                // NF-INF02-01: validate and content_hash prove the canonical
                // form (INF-02), so a non-canonical image is refused;
                // reencode is the repair path.
                try {
                    ActiveInfinity.validate(image);
                    throw new IllegalStateException(path + ": non-canonical image was validated");
                } catch (ActiveInfinity.Error error) {
                    if (!error.code().equals("infinity/not-canonical")) {
                        throw new IllegalStateException(path + ": wrong code " + error.code());
                    }
                }
                try {
                    ActiveInfinity.contentHashHex(image);
                    throw new IllegalStateException(path + ": non-canonical image was hashed");
                } catch (ActiveInfinity.Error error) {
                    if (!error.code().equals("infinity/not-canonical")) {
                        throw new IllegalStateException(path + ": wrong code " + error.code());
                    }
                }
                // INF-POLY-03: the binding surfaces validateCanonical; it
                // must refuse the non-canonical image with the same code.
                try {
                    ActiveInfinity.validateCanonical(image);
                    throw new IllegalStateException(path + ": non-canonical image passed validateCanonical");
                } catch (ActiveInfinity.Error error) {
                    if (!error.code().equals("infinity/not-canonical")) {
                        throw new IllegalStateException(path + ": wrong code " + error.code());
                    }
                }
            } else {
                ActiveInfinity.validate(image);
                ActiveInfinity.validateCanonical(image);
                String actual = ActiveInfinity.contentHashHex(image);
                if (!actual.equals(expected)) {
                    throw new IllegalStateException(path + ": hash " + actual + ", want " + expected);
                }
            }
            byte[] canonical = ActiveInfinity.reencode(image);
            if (path.contains("non_canonical")) {
                if (Arrays.equals(canonical, image)) {
                    throw new IllegalStateException(path + ": expected changed bytes");
                }
                ActiveInfinity.validate(canonical);
            } else if (!Arrays.equals(canonical, image)) {
                throw new IllegalStateException(path + ": canonical bytes changed");
            }
            checked++;
        }
        // INF-POLY-03: pin the exact count, derived from the manifest
        // -- a slack `>=` let a dropped vector pass silently.
        int valid = manifest.split("\"kind\": \"valid\"", -1).length - 1;
        if (checked != valid) {
            throw new IllegalStateException("manifest vectors were not exercised: " + checked + " of " + valid);
        }

        // INF-POLY-02: every invalid vector must be refused with exactly
        // the manifest's expected_code. INF-FFI-02: the two limits-dependent
        // ones (limit, too_deep) go through validateWithLimits with the
        // narrowed budget from the entry's options.limits (max_nodes:1,
        // max_depth:8); the rest go through validateCanonical.
        // invalid_stream vectors are CLI-only: no stream decode exists in
        // the FFI.
        int invalidChecked = 0;
        Matcher invalidMatcher = INVALID_CASE.matcher(manifest);
        while (invalidMatcher.find()) {
            String invalidName = invalidMatcher.group(1);
            String invalidPath = invalidMatcher.group(2);
            String invalidOptions = invalidMatcher.group(3);
            String expectedCode = invalidMatcher.group(4);
            byte[] invalidImage = Files.readAllBytes(root.resolve(invalidPath));
            try {
                Matcher limitsMatcher = LIMITS_OPTION.matcher(invalidOptions);
                if (limitsMatcher.find()) {
                    String[] parts = limitsMatcher.group(1).split(":", 2);
                    Limits limits = Limits.defaults();
                    limits.setField(parts[0], Long.parseLong(parts[1]));
                    ActiveInfinity.validateWithLimits(invalidImage, limits);
                } else {
                    ActiveInfinity.validateCanonical(invalidImage);
                }
                throw new IllegalStateException(invalidName + ": invalid image was accepted");
            } catch (ActiveInfinity.Error error) {
                if (!error.code().equals(expectedCode)) {
                    throw new IllegalStateException(invalidName + ": wrong code " + error.code());
                }
            }
            invalidChecked++;
        }
        int invalidTotal = manifest.split("\"kind\": \"invalid\"", -1).length - 1;
        if (invalidChecked != invalidTotal) {
            throw new IllegalStateException("manifest invalid vectors were not exercised: " + invalidChecked + " of " + invalidTotal);
        }

        String source = "port = 8080\nname = \"java\"\n";
        byte[] first = ActiveInfinity.fromActive(source, "java.active");
        byte[] second = ActiveInfinity.fromActive(source, "java.active");
        if (!Arrays.equals(first, second)) {
            throw new IllegalStateException("Active source encoding is not deterministic");
        }
        ActiveInfinity.validate(first);

        // A supplementary character is valid standard UTF-8. GetStringUTFChars
        // would have produced CESU-8 for it, which the shim refuses; the Java
        // side now encodes the name itself.
        byte[] unicodeName = ActiveInfinity.fromActive(source, "java-\uD83D\uDE00.active");
        ActiveInfinity.validate(unicodeName);

        byte[] full = Files.readAllBytes(root.resolve("tests/vectors/valid/full.ainf"));
        // A claimed capacity larger than the array must be clamped by the shim;
        // trusting it would let Java overflow the native buffer.
        int[] claimed = {1 << 20};
        byte[] tiny = new byte[8];
        int clampStatus = Native.reencode(full, tiny, claimed);
        if (clampStatus != -2) {
            throw new IllegalStateException("a small array was not refused: " + clampStatus);
        }

        String json = ActiveInfinity.redactedJson(full);
        if (json.contains("CANARY_SECRET_")) {
            throw new IllegalStateException("secret canary survived redaction");
        }
        if (!json.stripLeading().startsWith("{") || !json.contains("\"secret\":\"***SECRET***\"")) {
            throw new IllegalStateException("redacted JSON looks wrong: " + json);
        }
        json.getBytes(StandardCharsets.UTF_8);

        try {
            ActiveInfinity.validate(new byte[] {(byte) 0xff, (byte) 0xff});
            throw new IllegalStateException("malformed input was accepted");
        } catch (ActiveInfinity.Error error) {
            if (!error.code().startsWith("infinity/")) {
                throw new IllegalStateException("unstable code " + error.code());
            }
        }

        System.out.printf("Java conformance PASS (%d vectors, ABI %d)%n", checked, ActiveInfinity.ABI);
    }
}
