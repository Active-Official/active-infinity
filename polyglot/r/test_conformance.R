# Conformance test for the R binding.
#
#   Rscript polyglot/r/test_conformance.R
#
# Validates every valid vector, reproduces its manifest content hash, re-encodes
# canonically, compiles Active text, and checks that the redaction canary never
# leaves the projection.

args <- commandArgs(trailingOnly = FALSE)
file_arg <- sub("^--file=", "", args[grep("^--file=", args)])
here <- if (length(file_arg) == 1 && nzchar(file_arg)) dirname(normalizePath(file_arg)) else getwd()
source(file.path(here, "active_infinity.R"))
root <- normalizePath(file.path(here, "..", ".."))

manifest <- paste(readLines(file.path(root, "conformance", "manifest.json"), warn = FALSE), collapse = "\n")
blocks <- strsplit(manifest, '"kind": "valid"', fixed = TRUE)[[1]][-1]
# INF-POLY-03: pin the exact count -- the manifest lists 5 valid
# vectors. A slack `< 4` let a dropped vector pass silently.
if (length(blocks) != 5) {
  stop("the manifest must list exactly five valid cases", call. = FALSE)
}

checked <- 0L
for (block in blocks) {
  match <- regexec(
    '"name": "([^"]+)"[\\s\\S]*?"path": "([^"]+)"[\\s\\S]*?"content_hash": "([0-9a-f]{64})"',
    block, perl = TRUE
  )
  captures <- regmatches(block, match)[[1]]
  if (length(captures) != 4) {
    next
  }
  name <- captures[2]
  path <- captures[3]
  expected <- captures[4]

  image <- readBin(file.path(root, path), "raw", file.size(file.path(root, path)))
  if (identical(name, "non_canonical")) {
    # NF-INF02-01: validate and content_hash prove the canonical form
    # (INF-02), so a non-canonical image is refused; reencode is the repair
    # path.
    refused <- tryCatch(
      {
        ai_validate(image)
        FALSE
      },
      error = function(condition) {
        grepl("infinity/not-canonical", condition$message, fixed = TRUE)
      }
    )
    if (!isTRUE(refused)) stop("a non-canonical image was validated", call. = FALSE)
    refused <- tryCatch(
      {
        ai_content_hash_hex(image)
        FALSE
      },
      error = function(condition) {
        grepl("infinity/not-canonical", condition$message, fixed = TRUE)
      }
    )
    if (!isTRUE(refused)) stop("a non-canonical image was hashed", call. = FALSE)
    # INF-POLY-03: the binding surfaces ai_validate_canonical; it must
    # refuse the non-canonical image with the same code.
    refused <- tryCatch(
      {
        ai_validate_canonical(image)
        FALSE
      },
      error = function(condition) {
        grepl("infinity/not-canonical", condition$message, fixed = TRUE)
      }
    )
    if (!isTRUE(refused)) stop("a non-canonical image passed validate_canonical", call. = FALSE)
  } else {
    ai_validate(image)
    ai_validate_canonical(image)
    actual <- ai_content_hash_hex(image)
    if (!identical(actual, expected)) {
      stop(sprintf("%s: content hash %s, expected %s", name, actual, expected), call. = FALSE)
    }
  }
  canonical <- ai_reencode(image)
  same <- identical(canonical, image)
  if (identical(name, "non_canonical")) {
    if (same) stop("a non-canonical image re-encoded unchanged", call. = FALSE)
    ai_validate(canonical)
  } else if (!same) {
    stop(sprintf("%s: re-encode changed canonical bytes", name), call. = FALSE)
  }
  checked <- checked + 1L
}

# INF-POLY-02: every invalid vector must be refused with exactly the
# manifest's expected_code. INF-FFI-02: the two limits-dependent ones
# (limit, too_deep) go through ai_validate_with_limits with the narrowed
# budget from the entry's options.limits (max_nodes:1, max_depth:8); the
# rest go through ai_validate_canonical. invalid_stream vectors are
# CLI-only: no stream decode exists in the FFI. The split is on
# `"kind": "invalid"` with the closing quote, so `"kind": "invalid_stream"`
# never splits.
invalid_blocks <- strsplit(manifest, '"kind": "invalid"', fixed = TRUE)[[1]][-1]
if (length(invalid_blocks) != 35) {
  stop("the manifest must list exactly 35 invalid cases", call. = FALSE)
}
invalid_checked <- 0L
for (block in invalid_blocks) {
  match <- regexec(
    '"name": "([^"]+)"[\\s\\S]*?"path": "([^"]+)"[\\s\\S]*?"options": \\{([^}]*)\\}[\\s\\S]*?"expected_code": "([^"]+)"',
    block, perl = TRUE
  )
  captures <- regmatches(block, match)[[1]]
  if (length(captures) != 5) {
    stop("the manifest invalid case scan failed", call. = FALSE)
  }
  name <- captures[2]
  path <- captures[3]
  options <- captures[4]
  expected_code <- captures[5]
  image <- readBin(file.path(root, path), "raw", file.size(file.path(root, path)))
  refused <- tryCatch(
    {
      limits_match <- regexec('"limits": "([^"]+)"', options, perl = TRUE)
      limits_captures <- regmatches(options, limits_match)[[1]]
      if (length(limits_captures) == 2) {
        parts <- strsplit(limits_captures[2], ":", fixed = TRUE)[[1]]
        limits <- ai_limits_default()
        limits <- ai_limits_set(limits, parts[1], as.numeric(parts[2]))
        ai_validate_with_limits(image, limits)
      } else {
        ai_validate_canonical(image)
      }
      FALSE
    },
    error = function(condition) {
      identical(condition$message, sprintf("Active Infinity: %s", expected_code))
    }
  )
  if (!isTRUE(refused)) {
    stop(sprintf("%s: invalid image was not refused with %s", name, expected_code), call. = FALSE)
  }
  invalid_checked <- invalid_checked + 1L
}
if (invalid_checked != 35L) {
  stop("the manifest invalid vectors were not exercised", call. = FALSE)
}

source_text <- "port = 8080\nname = \"r\"\n"
first <- ai_from_active(source_text, "r.active")
second <- ai_from_active(source_text, "r.active")
if (!identical(first, second)) stop("from_active is not deterministic", call. = FALSE)
ai_validate(first)

full <- readBin(file.path(root, "tests", "vectors", "valid", "full.ainf"), "raw",
                file.size(file.path(root, "tests", "vectors", "valid", "full.ainf")))
json <- ai_redacted_json(full)
if (grepl("CANARY_SECRET_", json, fixed = TRUE)) {
  stop("the redacted projection leaked the canary", call. = FALSE)
}
if (!identical(substr(json, 1, 1), "{")) {
  stop("the redacted projection is not JSON", call. = FALSE)
}

refused <- tryCatch(
  {
    ai_validate(as.raw(c(0xff, 0xff, 0xff)))
    FALSE
  },
  error = function(condition) {
    grepl("^Active Infinity: infinity/", condition$message)
  }
)
if (!refused) stop("malformed input was accepted", call. = FALSE)

cat(sprintf("R conformance PASS (%d vectors, ABI %d)\n", checked, ai_abi_version()))
