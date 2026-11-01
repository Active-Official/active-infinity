#!/usr/bin/env Rscript
# Thin Active RPC client over native ARP1 on TCP (R).
#
# Base R only: socketConnection plus writeBin/readBin. Run against
# `active-rpc/examples/thin_peer.rs`:
#
#   ACTIVE_RPC_ADDR=127.0.0.1:54321 \
#   ACTIVE_RPC_CAP=<32 hex chars> \
#   ACTIVE_RPC_PAYLOAD=tests/vectors/valid/full.ainf \
#   Rscript polyglot/rpc/r_client.r
#
# ARP1 is little-endian throughout. R has no unsigned 64-bit integer, so a u64
# is written as two u32 halves (low first) and read the same way: the values in
# this protocol are request ids and byte counts, both far below 2^32 in
# practice and neither ever interpreted as a signed R integer.

MAGIC <- charToRaw("ARP1")
VERSION <- 1L
KIND_REQUEST <- 1L
KIND_RESPONSE <- 2L
KIND_ERROR <- 3L
BUDGET <- c(10000, 64 * 1024 * 1024, 5000, 100000, 256, 100000, 10000000)

fail <- function(...) {
  cat(paste0(..., collapse = ""), "\n", file = stderr())
  quit(status = 1)
}

write_u16 <- function(con, value) {
  if (value < 0 || value > 65535) fail("u16 out of range: ", value)
  writeBin(as.integer(value), con, size = 2L, endian = "little")
}

write_u32 <- function(con, value) {
  if (value < 0 || value > 2^32 - 1) fail("u32 out of range: ", value)
  writeBin(as.integer(value), con, size = 4L, endian = "little")
}

write_u64 <- function(con, value) {
  if (value < 0 || value > 2^53) fail("u64 out of the exact-integer range: ", value)
  low <- value %% 2^32
  high <- floor(value / 2^32)
  write_u32(con, low)
  write_u32(con, high)
}

write_bytes <- function(con, value) {
  writeBin(as.raw(value), con)
}

read_exact <- function(con, count) {
  out <- raw(0)
  while (length(out) < count) {
    chunk <- readBin(con, "raw", n = count - length(out))
    if (length(chunk) == 0) fail("connection closed after ", length(out), " of ", count, " bytes")
    out <- c(out, chunk)
  }
  out
}

read_u32 <- function(bytes, offset) {
  # offset is 0-based from the start of the frame; R vectors are 1-based.
  piece <- bytes[(offset + 1):(offset + 4)]
  connection <- rawConnection(piece)
  on.exit(close(connection), add = TRUE)
  # Lengths and counts stay far below 2^31, so the signed reading is exact.
  as.numeric(readBin(connection, "integer", n = 1L, size = 4L, endian = "little"))
}

read_u64 <- function(bytes, offset) {
  read_u32(bytes, offset) + read_u32(bytes, offset + 4) * 2^32
}

send_cap_descriptor <- function(con, cap_id) {
  write_bytes(con, cap_id)
  write_u32(con, 1) # one method
  write_u32(con, 4)
  write_bytes(con, charToRaw("echo"))
  for (value in BUDGET) write_u64(con, value)
  write_bytes(con, as.raw(c(0, 0, 0))) # read_only, redact, no path scope
}

send_request <- function(con, request_id, method, payload, cap_id) {
  frame <- rawConnection(raw(0), open = "wb")
  write_bytes(frame, MAGIC)
  write_bytes(frame, as.raw(c(VERSION, KIND_REQUEST)))
  write_u16(frame, 0) # flags
  write_u64(frame, request_id)
  encoded_method <- charToRaw(method)
  write_u32(frame, length(encoded_method))
  write_bytes(frame, encoded_method)
  write_u32(frame, 0) # no positional arguments
  write_u32(frame, length(payload))
  write_bytes(frame, payload)
  if (is.null(cap_id)) {
    write_u32(frame, 0)
  } else {
    write_u32(frame, 1)
    send_cap_descriptor(frame, cap_id)
  }
  body <- rawConnectionValue(frame)
  close(frame)
  write_u32(con, length(body))
  write_bytes(con, body)
}

call <- function(address, request_id, method, payload, cap_id) {
  parts <- strsplit(address, ":", fixed = TRUE)[[1]]
  host <- parts[1]
  port <- as.integer(parts[2])
  con <- socketConnection(host, port, open = "a+b", blocking = TRUE, timeout = 10)
  on.exit(close(con), add = TRUE)
  send_request(con, request_id, method, payload, cap_id)
  header <- read_exact(con, 4L)
  length <- read_u32(header, 0)
  if (length > 1024 * 1024) fail("response frame exceeds the ceiling: ", length)
  body <- read_exact(con, length)
  list(
    kind = as.integer(body[6]),
    request_id = read_u64(body, 8L),
    method = rawToChar(body[21:(20 + read_u32(body, 16L))]),
    body = body
  )
}

# Value and argument tags of ARP1. Skipping is enough here: the client checks
# the payload, not the value, and a malformed body must fail closed.
skip_value <- function(bytes, offset, depth = 0L) {
  if (depth > 64L) fail("value nesting exceeds the ceiling")
  tag <- as.integer(bytes[offset + 1])
  offset <- offset + 1L
  if (tag == 1L) {
    return(offset + 1L)
  }
  if (tag == 2L || tag == 3L) {
    return(offset + 8L)
  }
  if (tag == 4L || tag == 8L || tag == 9L) {
    return(offset + 4L + read_u32(bytes, offset))
  }
  if (tag == 5L) {
    count <- read_u32(bytes, offset)
    offset <- offset + 4L
    for (index in seq_len(count)) offset <- skip_value(bytes, offset, depth + 1L)
    return(offset)
  }
  if (tag == 6L) {
    count <- read_u32(bytes, offset)
    offset <- offset + 4L
    for (index in seq_len(count)) {
      key_length <- read_u32(bytes, offset)
      offset <- skip_value(bytes, offset + 4L + key_length, depth + 1L)
    }
    return(offset)
  }
  if (tag == 0L || tag == 7L) {
    return(offset)
  }
  fail("unknown value tag ", tag)
}

skip_args <- function(bytes, offset, count) {
  for (index in seq_len(count)) {
    tag <- as.integer(bytes[offset + 1])
    offset <- offset + 1L
    if (tag == 0L) {
      offset <- skip_value(bytes, offset)
    } else if (tag == 1L) {
      offset <- offset + 8L
    } else if (tag == 2L) {
      offset <- offset + 16L
    } else {
      fail("unknown argument tag ", tag)
    }
  }
  offset
}

# The method name sits at offset 20; the payload follows the arguments. Reading
# it back byte-for-byte is the payload check.
response_payload <- function(body) {
  method_length <- read_u32(body, 16L)
  offset <- 20L + method_length
  argument_count <- read_u32(body, offset)
  offset <- skip_args(body, offset + 4L, argument_count)
  payload_length <- read_u32(body, offset)
  offset <- offset + 4L
  if (offset + payload_length > length(body)) fail("truncated response payload")
  body[(offset + 1):(offset + payload_length)]
}

main <- function() {
  address <- Sys.getenv("ACTIVE_RPC_ADDR")
  if (nchar(address) == 0) fail("ACTIVE_RPC_ADDR is not set")
  cap_text <- Sys.getenv("ACTIVE_RPC_CAP")
  if (nchar(cap_text) != 32) fail("ACTIVE_RPC_CAP must be 32 hex characters")
  cap_id <- as.raw(strtoi(substring(cap_text, seq(1, 31, 2), seq(2, 32, 2)), base = 16L))
  payload_path <- Sys.getenv("ACTIVE_RPC_PAYLOAD", "tests/vectors/valid/full.ainf")
  payload <- readBin(payload_path, "raw", n = file.info(payload_path)$size)

  echoed <- call(address, 42, "echo", payload, cap_id)
  if (echoed$kind != KIND_RESPONSE) fail("echo was not a response: kind ", echoed$kind)
  if (echoed$request_id != 42) fail("echo echoed request id ", echoed$request_id)
  if (!identical(response_payload(echoed$body), payload)) fail("the AINF payload was not echoed")

  refused <- call(address, 43, "refuse", payload, cap_id)
  if (refused$kind != KIND_ERROR) fail("an unknown method was not refused")
  if (refused$method != "rpc/method-not-granted") fail("wrong refusal code: ", refused$method)

  anonymous <- call(address, 44, "echo", payload, NULL)
  if (anonymous$kind != KIND_ERROR) fail("a call without a capability was not refused")
  if (anonymous$method != "rpc/unknown-capability") fail("wrong refusal code: ", anonymous$method)

  cat("R thin RPC PASS (echo, refusal, missing capability)\n")
}

main()
