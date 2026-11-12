import ai.activeinfinity.ActiveInfinity
import ai.activeinfinity.Limits

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

  // INF-POLY-02: the invalid-case pattern. It anchors on
  // `"kind": "invalid"` with the closing quote, so it never matches
  // `"kind": "invalid_stream"`; the `.*?` spans the options object,
  // which sits between path and expected_code and never contains an
  // expected_code of its own.
  private val InvalidCase: Regex =
    """(?s)"kind": "invalid".*?"name": "([^"]+)".*?"path": "([^"]+)".*?"options": \{([^}]*)\}.*?"expected_code": "([^"]+)"""".r
  private val LimitsOption =
    """(?s)"limits": "([^"]+)"""".r

  def main(args: Array[String]): Unit = {
    val root = new File(".").getAbsoluteFile
    val manifest = scala.io.Source.fromFile(new File(root, "conformance/manifest.json")).mkString

    var checked = 0
    for (m <- Case.findAllMatchIn(manifest)) {
      val path = m.group(1)
      val expected = m.group(2)
      if (path.contains("/valid/")) {
        val image = java.nio.file.Files.readAllBytes(root.toPath.resolve(path))
        if (path.contains("non_canonical")) {
          // NF-INF02-01: validate and content_hash prove the canonical
          // form (INF-02), so a non-canonical image is refused; reencode
          // is the repair path.
          try {
            ActiveInfinity.validate(image)
            throw new IllegalStateException(path + ": non-canonical image was validated")
          } catch {
            case error: ActiveInfinity.Error =>
              require(error.code() == "infinity/not-canonical", s"$path: wrong code ${error.code()}")
          }
          try {
            ActiveInfinity.contentHashHex(image)
            throw new IllegalStateException(path + ": non-canonical image was hashed")
          } catch {
            case error: ActiveInfinity.Error =>
              require(error.code() == "infinity/not-canonical", s"$path: wrong code ${error.code()}")
          }
          // INF-POLY-03: the binding surfaces validateCanonical; it must
          // refuse the non-canonical image with the same code.
          try {
            ActiveInfinity.validateCanonical(image)
            throw new IllegalStateException(path + ": non-canonical image passed validateCanonical")
          } catch {
            case error: ActiveInfinity.Error =>
              require(error.code() == "infinity/not-canonical", s"$path: wrong code ${error.code()}")
          }
        } else {
          ActiveInfinity.validate(image)
          ActiveInfinity.validateCanonical(image)
          val actual = ActiveInfinity.contentHashHex(image)
          require(actual == expected, s"$path: hash $actual, want $expected")
        }
        val canonical = ActiveInfinity.reencode(image)
        if (path.contains("non_canonical")) {
          require(!java.util.Arrays.equals(canonical, image), s"$path: expected changed bytes")
          ActiveInfinity.validate(canonical)
        } else {
          require(java.util.Arrays.equals(canonical, image), s"$path: canonical bytes changed")
        }
        checked += 1
      }
    }
    // INF-POLY-03: pin the exact count, derived from the manifest --
    // a slack `>=` let a dropped vector pass silently.
    val valid = "\"kind\": \"valid\"".r.findAllIn(manifest).length
    require(checked == valid, s"manifest vectors were not exercised: $checked of $valid")

    // INF-POLY-02: every invalid vector must be refused with exactly the
    // manifest's expected_code. INF-FFI-02: the two limits-dependent ones
    // (limit, too_deep) go through validateWithLimits with the narrowed
    // budget from the entry's options.limits (max_nodes:1, max_depth:8);
    // the rest go through validateCanonical. invalid_stream vectors are
    // CLI-only: no stream decode exists in the FFI.
    var invalidChecked = 0
    for (m <- InvalidCase.findAllMatchIn(manifest)) {
      val invalidName = m.group(1)
      val invalidPath = m.group(2)
      val invalidOptions = m.group(3)
      val expectedCode = m.group(4)
      val invalidImage = java.nio.file.Files.readAllBytes(root.toPath.resolve(invalidPath))
      try {
        LimitsOption.findFirstMatchIn(invalidOptions) match {
          case Some(limitsMatch) =>
            val parts = limitsMatch.group(1).split(":", 2)
            val limits = Limits.defaults()
            limits.setField(parts(0), parts(1).toLong)
            ActiveInfinity.validateWithLimits(invalidImage, limits)
          case None =>
            ActiveInfinity.validateCanonical(invalidImage)
        }
        throw new IllegalStateException(invalidName + ": invalid image was accepted")
      } catch {
        case error: ActiveInfinity.Error =>
          require(error.code() == expectedCode, s"$invalidName: wrong code ${error.code()}")
      }
      invalidChecked += 1
    }
    val invalidTotal = "\"kind\": \"invalid\"".r.findAllIn(manifest).length
    require(invalidChecked == invalidTotal, s"manifest invalid vectors were not exercised: $invalidChecked of $invalidTotal")

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
