import ai.activeinfinity.ActiveInfinity
import ai.activeinfinity.Limits
import java.io.File

/**
 * Kotlin/JVM conformance: reuses the Java binding (same JVM classes and JNI
 * glue), so bytes cannot drift between the two languages.
 *
 * Run from the repository root after `polyglot/java/build.sh`:
 *   kotlinc -cp polyglot/java/classes -include-runtime -d conformance.jar \
 *       polyglot/kotlin/src/Conformance.kt
 *   java -Djava.library.path=polyglot/java -cp conformance.jar:polyglot/java/classes ConformanceKt
 * On Windows the JVM also needs the bridge directory on PATH, so the
 * bridge's own dependency (active_infinity_ffi.dll) is found:
 *   PATH=polyglot/java:$PATH java -Djava.library.path=polyglot/java \
 *       -cp conformance.jar:polyglot/java/classes ConformanceKt
 * (NF-XPL06-01: a plain LoadLibrary does not search the loaded module's
 * directory for its dependencies.)
 */
fun main() {
    val root = File(".").absoluteFile
    val manifest = File(root, "conformance/manifest.json").readText()
    val case = Regex("\"path\"\\s*:\\s*\"([^\"]+)\".*?\"content_hash\"\\s*:\\s*\"([^\"]+)\"", RegexOption.DOT_MATCHES_ALL)
    // INF-POLY-02: the invalid-case pattern. It anchors on
    // `"kind": "invalid"` with the closing quote, so it never matches
    // `"kind": "invalid_stream"`; the `.*?` spans the options object,
    // which sits between path and expected_code and never contains an
    // expected_code of its own.
    val invalidCase = Regex("\"kind\"\\s*:\\s*\"invalid\".*?\"name\"\\s*:\\s*\"([^\"]+)\".*?\"path\"\\s*:\\s*\"([^\"]+)\".*?\"options\"\\s*:\\s*\\{([^}]*)\\}.*?\"expected_code\"\\s*:\\s*\"([^\"]+)\"", RegexOption.DOT_MATCHES_ALL)
    val limitsOption = Regex("\"limits\"\\s*:\\s*\"([^\"]+)\"")

    var checked = 0
    for (match in case.findAll(manifest)) {
        val path = match.groupValues[1]
        val expected = match.groupValues[2]
        if (!path.contains("/valid/")) continue
        val image = File(root, path).readBytes()
        if (path.contains("non_canonical")) {
            // NF-INF02-01: validate and content_hash prove the canonical
            // form (INF-02), so a non-canonical image is refused; reencode
            // is the repair path.
            try {
                ActiveInfinity.validate(image)
                error("$path: non-canonical image was validated")
            } catch (e: ActiveInfinity.Error) {
                check(e.code() == "infinity/not-canonical") { "$path: wrong code ${e.code()}" }
            }
            try {
                ActiveInfinity.contentHashHex(image)
                error("$path: non-canonical image was hashed")
            } catch (e: ActiveInfinity.Error) {
                check(e.code() == "infinity/not-canonical") { "$path: wrong code ${e.code()}" }
            }
            // INF-POLY-03: the binding surfaces validateCanonical; it must
            // refuse the non-canonical image with the same code.
            try {
                ActiveInfinity.validateCanonical(image)
                error("$path: non-canonical image passed validateCanonical")
            } catch (e: ActiveInfinity.Error) {
                check(e.code() == "infinity/not-canonical") { "$path: wrong code ${e.code()}" }
            }
        } else {
            ActiveInfinity.validate(image)
            ActiveInfinity.validateCanonical(image)
            val actual = ActiveInfinity.contentHashHex(image)
            check(actual == expected) { "$path: hash $actual, want $expected" }
        }
        val canonical = ActiveInfinity.reencode(image)
        if (path.contains("non_canonical")) {
            check(!canonical.contentEquals(image)) { "$path: expected changed bytes" }
            ActiveInfinity.validate(canonical)
        } else {
            check(canonical.contentEquals(image)) { "$path: canonical bytes changed" }
        }
        checked++
    }
    // INF-POLY-03: pin the exact count, derived from the manifest --
    // a slack `>=` let a dropped vector pass silently.
    val valid = Regex("\"kind\": \"valid\"").findAll(manifest).count()
    check(checked == valid) { "manifest vectors were not exercised: $checked of $valid" }

    // INF-POLY-02: every invalid vector must be refused with exactly the
    // manifest's expected_code. INF-FFI-02: the two limits-dependent ones
    // (limit, too_deep) go through validateWithLimits with the narrowed
    // budget from the entry's options.limits (max_nodes:1, max_depth:8);
    // the rest go through validateCanonical. invalid_stream vectors are
    // CLI-only: no stream decode exists in the FFI.
    var invalidChecked = 0
    for (match in invalidCase.findAll(manifest)) {
        val invalidName = match.groupValues[1]
        val invalidPath = match.groupValues[2]
        val invalidOptions = match.groupValues[3]
        val expectedCode = match.groupValues[4]
        val invalidImage = File(root, invalidPath).readBytes()
        try {
            val limitsMatch = limitsOption.find(invalidOptions)
            if (limitsMatch != null) {
                val parts = limitsMatch.groupValues[1].split(":", limit = 2)
                val limits = Limits.defaults()
                limits.setField(parts[0], parts[1].toLong())
                ActiveInfinity.validateWithLimits(invalidImage, limits)
            } else {
                ActiveInfinity.validateCanonical(invalidImage)
            }
            error("$invalidName: invalid image was accepted")
        } catch (e: ActiveInfinity.Error) {
            check(e.code() == expectedCode) { "$invalidName: wrong code ${e.code()}" }
        }
        invalidChecked++
    }
    val invalidTotal = Regex("\"kind\": \"invalid\"").findAll(manifest).count()
    check(invalidChecked == invalidTotal) { "manifest invalid vectors were not exercised: $invalidChecked of $invalidTotal" }

    val source = "port = 8080\nname = \"kotlin\"\n"
    val first = ActiveInfinity.fromActive(source, "kotlin.active")
    val second = ActiveInfinity.fromActive(source, "kotlin.active")
    check(first.contentEquals(second)) { "Active source encoding is not deterministic" }
    ActiveInfinity.validate(first)

    val full = File(root, "tests/vectors/valid/full.ainf").readBytes()
    val json = ActiveInfinity.redactedJson(full)
    check(!json.contains("CANARY_SECRET_")) { "secret canary survived redaction" }
    check(json.trimStart().startsWith("{")) { "redacted JSON looks wrong" }

    try {
        ActiveInfinity.validate(byteArrayOf(0xff.toByte(), 0xff.toByte()))
        error("malformed input was accepted")
    } catch (error: ActiveInfinity.Error) {
        check(error.code().startsWith("infinity/")) { "unstable code ${error.code()}" }
    }

    println("Kotlin/JVM conformance PASS ($checked vectors, ABI ${ActiveInfinity.ABI})")
}
