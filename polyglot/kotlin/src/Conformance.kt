import ai.activeinfinity.ActiveInfinity
import java.io.File

/**
 * Kotlin/JVM conformance: reuses the Java binding (same JVM classes and JNI
 * glue), so bytes cannot drift between the two languages.
 *
 * Run from the repository root after `polyglot/java/build.sh`:
 *   kotlinc -cp polyglot/java/classes -include-runtime -d conformance.jar \
 *       polyglot/kotlin/src/Conformance.kt
 *   java -Djava.library.path=polyglot/java -cp conformance.jar:polyglot/java/classes ConformanceKt
 */
fun main() {
    val root = File(".").absoluteFile
    val manifest = File(root, "conformance/manifest.json").readText()
    val case = Regex("\"path\"\\s*:\\s*\"([^\"]+)\".*?\"content_hash\"\\s*:\\s*\"([^\"]+)\"", RegexOption.DOT_MATCHES_ALL)

    var checked = 0
    for (match in case.findAll(manifest)) {
        val path = match.groupValues[1]
        val expected = match.groupValues[2]
        if (!path.contains("/valid/")) continue
        val image = File(root, path).readBytes()
        ActiveInfinity.validate(image)
        val actual = ActiveInfinity.contentHashHex(image)
        check(actual == expected) { "$path: hash $actual, want $expected" }
        val canonical = ActiveInfinity.reencode(image)
        if (path.contains("non_canonical")) {
            check(!canonical.contentEquals(image)) { "$path: expected changed bytes" }
        } else {
            check(canonical.contentEquals(image)) { "$path: canonical bytes changed" }
        }
        checked++
    }
    check(checked >= 4) { "manifest vectors were not exercised" }

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
