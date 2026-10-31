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

} // namespace detail

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
