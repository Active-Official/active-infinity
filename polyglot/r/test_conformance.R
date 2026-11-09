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
if (length(blocks) < 4) {
  stop("the manifest must list at least four valid cases", call. = FALSE)
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
  } else {
    ai_validate(image)
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
