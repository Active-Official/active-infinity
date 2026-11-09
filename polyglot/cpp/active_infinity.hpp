// Active Infinity C++ RAII wrapper over the C ABI.
//
// Header-only. Link against the shared or static library and include
// `active_infinity.h` (this header includes it).
//
//   #include "active_infinity.hpp"
//   auto image = active_infinity::Image::from_file("module.ainf");
//   image.validate();
//   auto hash = image.content_hash();
//   auto canonical = image.reencode();
//   auto json = image.redacted_json();

#ifndef ACTIVE_INFINITY_HPP
#define ACTIVE_INFINITY_HPP

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "active_infinity.h"

namespace active_infinity {

class Error : public std::runtime_error {
public:
  Error(std::string code, int32_t status)
      : std::runtime_error(code + " (status " + std::to_string(status) + ")"),
        code_(std::move(code)), status_(status) {}

  const std::string &code() const noexcept { return code_; }
  int32_t status() const noexcept { return status_; }

private:
  std::string code_;
  int32_t status_;
};

namespace detail {

inline std::string last_error() {
  const char *text = active_infinity_last_error();
  return text == nullptr ? std::string("infinity/unknown") : std::string(text);
}

inline void check(int32_t status, const char *what) {
  if (status != ACTIVE_INFINITY_OK) {
    throw Error(last_error(), status);
  }
  (void)what;
}

inline std::vector<uint8_t> output(int32_t (*call)(const uint8_t *, size_t,
                                                   uint8_t *, size_t *),
                                   const std::vector<uint8_t> &input) {
  size_t length = 0;
  int32_t status = call(input.data(), input.size(), nullptr, &length);
  if (status != ACTIVE_INFINITY_BUFFER_TOO_SMALL || length == 0) {
    check(status, "size query");
    return {};
  }
  std::vector<uint8_t> buffer(length);
  size_t capacity = length;
  check(call(input.data(), input.size(), buffer.data(), &capacity), "output");
  buffer.resize(capacity);
  return buffer;
}

// INF-FFI-02: output for the limits-parameterized outputs -- the same
// two-phase probe, with the limits struct threaded through the call.
inline std::vector<uint8_t>
output_with_limits(int32_t (*call)(const uint8_t *, size_t,
                                   const active_infinity_limits *, uint8_t *,
                                   size_t *),
                   const std::vector<uint8_t> &input,
                   const active_infinity_limits *limits) {
  size_t length = 0;
  int32_t status =
      call(input.data(), input.size(), limits, nullptr, &length);
  if (status != ACTIVE_INFINITY_BUFFER_TOO_SMALL || length == 0) {
    check(status, "size query");
    return {};
  }
  std::vector<uint8_t> buffer(length);
  size_t capacity = length;
  check(call(input.data(), input.size(), limits, buffer.data(), &capacity),
        "output");
  buffer.resize(capacity);
  return buffer;
}

} // namespace detail

// INF-FFI-02: a caller-supplied budget -- one ceiling per field, in the
// same order as the C `active_infinity_limits` struct. Build one with
// Limits::defaults(), set a ceiling with set(field, value), pass it to
// Image::validate_with_limits / decode_with_limits. A default-constructed
// Limits is all zeros (refused by the FFI as an invalid argument); use
// defaults() for the library budget.
struct Limits {
  uint32_t max_nodes_ = 0;
  uint32_t max_edges_ = 0;
  uint32_t max_children_ = 0;
  uint32_t max_fields_ = 0;
  uint32_t max_parts_ = 0;
  uint32_t max_strings_ = 0;
  uint32_t max_string_bytes_ = 0;
  uint32_t max_blobs_ = 0;
  uint32_t max_blob_bytes_ = 0;
  uint32_t max_annotations_ = 0;
  uint32_t max_units_ = 0;
  uint32_t max_types_ = 0;
  uint32_t max_aux_ = 0;
  uint32_t max_numbers_ = 0;
  uint32_t max_secrets_ = 0;
  uint32_t max_secret_bytes_ = 0;
  uint32_t max_extensions_ = 0;
  uint32_t max_prov_bytes_ = 0;
  uint32_t max_prov_entries_ = 0;
  uint32_t max_hashes_ = 0;
  uint32_t max_bindings_ = 0;
  uint64_t max_total_bytes_ = 0;
  uint64_t max_decoded_bytes_ = 0;
  uint32_t max_depth_ = 0;

  static Limits defaults() {
    Limits limits;
    detail::check(active_infinity_limits_default(&limits.storage()),
                  "limits default");
    return limits;
  }

  // Set one ceiling by its C field name. Throws on an unknown name.
  void set(const std::string &name, uint64_t value) {
    if (name == "max_nodes") { max_nodes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_edges") { max_edges_ = static_cast<uint32_t>(value); return; }
    if (name == "max_children") { max_children_ = static_cast<uint32_t>(value); return; }
    if (name == "max_fields") { max_fields_ = static_cast<uint32_t>(value); return; }
    if (name == "max_parts") { max_parts_ = static_cast<uint32_t>(value); return; }
    if (name == "max_strings") { max_strings_ = static_cast<uint32_t>(value); return; }
    if (name == "max_string_bytes") { max_string_bytes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_blobs") { max_blobs_ = static_cast<uint32_t>(value); return; }
    if (name == "max_blob_bytes") { max_blob_bytes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_annotations") { max_annotations_ = static_cast<uint32_t>(value); return; }
    if (name == "max_units") { max_units_ = static_cast<uint32_t>(value); return; }
    if (name == "max_types") { max_types_ = static_cast<uint32_t>(value); return; }
    if (name == "max_aux") { max_aux_ = static_cast<uint32_t>(value); return; }
    if (name == "max_numbers") { max_numbers_ = static_cast<uint32_t>(value); return; }
    if (name == "max_secrets") { max_secrets_ = static_cast<uint32_t>(value); return; }
    if (name == "max_secret_bytes") { max_secret_bytes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_extensions") { max_extensions_ = static_cast<uint32_t>(value); return; }
    if (name == "max_prov_bytes") { max_prov_bytes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_prov_entries") { max_prov_entries_ = static_cast<uint32_t>(value); return; }
    if (name == "max_hashes") { max_hashes_ = static_cast<uint32_t>(value); return; }
    if (name == "max_bindings") { max_bindings_ = static_cast<uint32_t>(value); return; }
    if (name == "max_total_bytes") { max_total_bytes_ = static_cast<uint64_t>(value); return; }
    if (name == "max_decoded_bytes") { max_decoded_bytes_ = static_cast<uint64_t>(value); return; }
    if (name == "max_depth") { max_depth_ = static_cast<uint32_t>(value); return; }
    throw Error("infinity/invalid-argument", -1);
  }

  const active_infinity_limits &storage() const noexcept {
    return reinterpret_cast<const active_infinity_limits &>(*this);
  }
  active_infinity_limits &storage() noexcept {
    return reinterpret_cast<active_infinity_limits &>(*this);
  }
};

// The C++ struct must lay out exactly like the C struct (same field order
// and types, standard layout) for the reinterpret_cast in
// Limits::storage() to be sound. These asserts pin that.
static_assert(sizeof(Limits) == sizeof(active_infinity_limits),
              "Limits must match the C struct size");
static_assert(alignof(Limits) == alignof(active_infinity_limits),
              "Limits must match the C struct alignment");

class Image {
public:
  Image() = default;
  explicit Image(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {}

  static Image from_file(const std::string &path) {
    FILE *file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) {
      throw Error("infinity/io", -1);
    }
    std::vector<uint8_t> bytes;
    uint8_t chunk[64 * 1024];
    size_t read = 0;
    while ((read = std::fread(chunk, 1, sizeof chunk, file)) > 0) {
      bytes.insert(bytes.end(), chunk, chunk + read);
    }
    std::fclose(file);
    return Image(std::move(bytes));
  }

  const std::vector<uint8_t> &bytes() const noexcept { return bytes_; }

  Image &validate() {
    detail::check(active_infinity_validate(bytes_.data(), bytes_.size()),
                  "validate");
    return *this;
  }

  // INF-POLY-03: `validate` already proves the canonical form (INF-02);
  // this states the requirement explicitly.
  Image &validate_canonical() {
    detail::check(
        active_infinity_validate_canonical(bytes_.data(), bytes_.size()),
        "validate canonical");
    return *this;
  }

  // INF-FFI-02: the limits-parameterized form of validate_canonical.
  Image &validate_with_limits(const Limits &limits) {
    detail::check(active_infinity_validate_with_limits(
                      bytes_.data(), bytes_.size(), &limits.storage()),
                  "validate with limits");
    return *this;
  }

  // INF-FFI-02: the limits-parameterized form of reencode.
  std::vector<uint8_t> decode_with_limits(const Limits &limits) const {
    return detail::output_with_limits(active_infinity_decode_with_limits,
                                      bytes_, &limits.storage());
  }

  std::vector<uint8_t> content_hash() const {
    std::vector<uint8_t> hash(32);
    detail::check(
        active_infinity_content_hash(bytes_.data(), bytes_.size(), hash.data()),
        "content hash");
    return hash;
  }

  std::string content_hash_hex() const {
    static const char *digits = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t byte : content_hash()) {
      out.push_back(digits[byte >> 4]);
      out.push_back(digits[byte & 0x0f]);
    }
    return out;
  }

  std::vector<uint8_t> reencode() const {
    return detail::output(active_infinity_reencode, bytes_);
  }

  std::string redacted_json() const {
    auto json = detail::output(active_infinity_redacted_json, bytes_);
    return std::string(json.begin(), json.end());
  }

private:
  std::vector<uint8_t> bytes_;
};

} // namespace active_infinity

#endif // ACTIVE_INFINITY_HPP
