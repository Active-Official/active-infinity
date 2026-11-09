# Active Infinity binding for R, using base R only (`.C`, no packages).
#
# The `.C` convention passes a pointer for every argument, so the lane builds a
# small shim (`native/active_infinity_r.c`) that adapts those pointers to the
# frozen C ABI. Point ACTIVE_INFINITY_LIB at the shared library.

.ai_state <- new.env(parent = emptyenv())

.ai_script_dir <- function() {
  args <- commandArgs(trailingOnly = FALSE)
  file_arg <- sub("^--file=", "", args[grep("^--file=", args)])
  if (length(file_arg) == 1 && nzchar(file_arg)) {
    return(dirname(normalizePath(file_arg)))
  }
  getwd()
}

ai_load <- function() {
  if (isTRUE(.ai_state$loaded)) {
    return(invisible(NULL))
  }
  configured <- Sys.getenv("ACTIVE_INFINITY_LIB", "")
  library <- if (nzchar(configured)) configured else "active_infinity_ffi"
  dyn.load(library)

  # XPL-INF-06: one shim candidate per OS. The list used to name only
  # `.dll` and `.so`, so on macOS no shim was ever found even when built.
  candidates <- c(
    Sys.getenv("ACTIVE_INFINITY_R_SHIM", ""),
    file.path(.ai_script_dir(), "active_infinity_r.dll"),
    file.path(.ai_script_dir(), "active_infinity_r.dylib"),
    file.path(.ai_script_dir(), "active_infinity_r.so"),
    file.path(getwd(), "polyglot", "r", "active_infinity_r.dll"),
    file.path(getwd(), "polyglot", "r", "active_infinity_r.dylib"),
    file.path(getwd(), "polyglot", "r", "active_infinity_r.so")
  )
  candidates <- candidates[nzchar(candidates)]
  existing <- candidates[file.exists(candidates)]
  if (length(existing) == 0) {
    stop("build polyglot/r/active_infinity_r.[dll|dylib|so] first", call. = FALSE)
  }
  dyn.load(existing[[1]])
  .ai_state$loaded <- TRUE
  invisible(NULL)
}

ai_last_error <- function() {
  ai_load()
  buffer <- raw(256)
  result <- .C("ai_r_last_error_text", buffer, as.double(length(buffer)))
  buffer <- result[[1]]
  nul <- which(buffer == as.raw(0))
  if (length(nul) == 0) {
    return(rawToChar(buffer))
  }
  if (nul[1] == 1) {
    return("")
  }
  rawToChar(buffer[seq_len(nul[1] - 1)])
}

ai_check <- function(status) {
  if (status == 0) {
    return(invisible(NULL))
  }
  stop(sprintf("Active Infinity: %s", ai_last_error()), call. = FALSE)
}

ai_abi_version <- function() {
  ai_load()
  value <- integer(1)
  result <- .C("ai_r_abi_version", value)
  result[[1]]
}

ai_validate <- function(image) {
  ai_load()
  status <- integer(1)
  result <- .C("ai_r_validate", image, as.double(length(image)), status)
  ai_check(result[[3]])
}

ai_validate_canonical <- function(image) {
  ai_load()
  status <- integer(1)
  result <- .C("ai_r_validate_canonical", image, as.double(length(image)), status)
  ai_check(result[[3]])
}

ai_content_hash <- function(image) {
  ai_load()
  out <- raw(32)
  status <- integer(1)
  result <- .C("ai_r_content_hash", image, as.double(length(image)), out, status)
  ai_check(result[[4]])
  result[[3]]
}

ai_content_hash_hex <- function(image) {
  paste(sprintf("%02x", as.integer(ai_content_hash(image))), collapse = "")
}

.ai_output_call <- function(symbol, image) {
  ai_load()
  length <- as.double(length(image))
  status <- integer(1)
  query <- .C(symbol, image, length, raw(0), as.double(0), status)
  capacity <- query[[4]]
  # -2 is the documented size query; anything else is a real refusal.
  if (query[[5]] != -2) ai_check(query[[5]])
  out <- raw(capacity)
  result <- .C(symbol, image, length, out, capacity, status)
  ai_check(result[[5]])
  result[[3]][seq_len(as.integer(result[[4]]))]
}

ai_reencode <- function(image) {
  .ai_output_call("ai_r_reencode", image)
}

ai_redacted_json <- function(image) {
  rawToChar(.ai_output_call("ai_r_redacted_json", image))
}

ai_from_active <- function(source, name) {
  ai_load()
  source_bytes <- charToRaw(enc2utf8(source))
  name_bytes <- c(charToRaw(enc2utf8(name)), as.raw(0))
  status <- integer(1)
  query <- .C(
    "ai_r_from_active", source_bytes, as.double(length(source_bytes)),
    name_bytes, raw(0), as.double(0), status
  )
  capacity <- query[[5]]
  if (query[[6]] != -2) ai_check(query[[6]])
  out <- raw(capacity)
  result <- .C(
    "ai_r_from_active", source_bytes, as.double(length(source_bytes)),
    name_bytes, out, capacity, status
  )
  ai_check(result[[6]])
  result[[4]][seq_len(as.integer(result[[5]]))]
}
