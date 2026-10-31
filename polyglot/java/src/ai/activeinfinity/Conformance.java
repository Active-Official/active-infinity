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
            ActiveInfinity.validate(image);
            String actual = ActiveInfinity.contentHashHex(image);
            if (!actual.equals(expected)) {
                throw new IllegalStateException(path + ": hash " + actual + ", want " + expected);
            }
            byte[] canonical = ActiveInfinity.reencode(image);
            if (path.contains("non_canonical")) {
                if (Arrays.equals(canonical, image)) {
                    throw new IllegalStateException(path + ": expected changed bytes");
                }
            } else if (!Arrays.equals(canonical, image)) {
                throw new IllegalStateException(path + ": canonical bytes changed");
            }
            checked++;
        }
        if (checked < 4) {
            throw new IllegalStateException("manifest vectors were not exercised");
        }

        String source = "port = 8080\nname = \"java\"\n";
        byte[] first = ActiveInfinity.fromActive(source, "java.active");
        byte[] second = ActiveInfinity.fromActive(source, "java.active");
        if (!Arrays.equals(first, second)) {
            throw new IllegalStateException("Active source encoding is not deterministic");
        }
        ActiveInfinity.validate(first);

        byte[] full = Files.readAllBytes(root.resolve("tests/vectors/valid/full.ainf"));
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
