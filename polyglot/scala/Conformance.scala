import ai.activeinfinity.ActiveInfinity

import java.io.File
import scala.util.matching.Regex

/**
 * Scala conformance: reuses the Java binding (JVM classes and JNI glue).
 *
 * Run from the repository root after `polyglot/java/build.sh`:
 *   bash polyglot/scala/build.sh
 */
object Conformance {
  private val Case: Regex =
    """(?s)"path"\s*:\s*"([^"]+)".*?"content_hash"\s*:\s*"([^"]+)"""".r

  def main(args: Array[String]): Unit = {
    val root = new File(".").getAbsoluteFile
    val manifest = scala.io.Source.fromFile(new File(root, "conformance/manifest.json")).mkString

    var checked = 0
    for (m <- Case.findAllMatchIn(manifest)) {
      val path = m.group(1)
      val expected = m.group(2)
      if (path.contains("/valid/")) {
        val image = java.nio.file.Files.readAllBytes(root.toPath.resolve(path))
        ActiveInfinity.validate(image)
        val actual = ActiveInfinity.contentHashHex(image)
        require(actual == expected, s"$path: hash $actual, want $expected")
        val canonical = ActiveInfinity.reencode(image)
        if (path.contains("non_canonical")) {
          require(!java.util.Arrays.equals(canonical, image), s"$path: expected changed bytes")
        } else {
          require(java.util.Arrays.equals(canonical, image), s"$path: canonical bytes changed")
        }
        checked += 1
      }
    }
    require(checked >= 4, "manifest vectors were not exercised")

    val source = "port = 8080\nname = \"scala\"\n"
    val first = ActiveInfinity.fromActive(source, "scala.active")
    val second = ActiveInfinity.fromActive(source, "scala.active")
    require(java.util.Arrays.equals(first, second), "Active source encoding is not deterministic")
    ActiveInfinity.validate(first)

    val full = java.nio.file.Files.readAllBytes(root.toPath.resolve("tests/vectors/valid/full.ainf"))
    val json = ActiveInfinity.redactedJson(full)
    require(!json.contains("CANARY_SECRET_"), "secret canary survived redaction")
    require(json.stripLeading().startsWith("{"), "redacted JSON looks wrong")

    try {
      ActiveInfinity.validate(Array(0xff.toByte, 0xff.toByte))
      throw new IllegalStateException("malformed input was accepted")
    } catch {
      case error: ActiveInfinity.Error =>
        require(error.code().startsWith("infinity/"), s"unstable code ${error.code()}")
    }

    println(s"Scala conformance PASS ($checked vectors, ABI ${ActiveInfinity.ABI})")
  }
}
