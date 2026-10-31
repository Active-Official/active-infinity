// C++ conformance test. Run from the repository root:
//   zig c++ -I ffi/active-infinity-ffi/include -I polyglot/cpp \
//       polyglot/cpp/test.cpp
//       ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib \ -o
//       test_cpp && ./test_cpp tests/vectors/valid/full.ainf

#include <cstdio>
#include <cstring>

#include "active_infinity.hpp"

int main(int argc, char **argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s <image.ainf>\n", argv[0]);
    return 2;
  }
  try {
    auto image = active_infinity::Image::from_file(argv[1]);
    image.validate();
    auto hash = image.content_hash_hex();
    std::printf("hash=%s\n", hash.c_str());
    auto canonical = image.reencode();
    if (canonical != image.bytes()) {
      std::fprintf(stderr, "re-encode changed canonical bytes\n");
      return 1;
    }
    auto json = image.redacted_json();
    if (json.find("CANARY_SECRET_") != std::string::npos) {
      std::fprintf(stderr, "redaction failed: canary survived\n");
      return 1;
    }
    std::printf("PASS\n");
    return 0;
  } catch (const active_infinity::Error &error) {
    std::fprintf(stderr, "FAIL %s\n", error.what());
    return 1;
  }
}
