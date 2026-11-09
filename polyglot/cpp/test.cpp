// C++ conformance test. Run from the repository root:
//   zig c++ -I ffi/active-infinity-ffi/include -I polyglot/cpp \
//       polyglot/cpp/test.cpp
//       ffi/active-infinity-ffi/target/release/active_infinity_ffi.dll.lib \ -o
//       test_cpp && ./test_cpp tests/vectors/valid/full.ainf
//   ./test_cpp tests/vectors/valid/full.ainf <content_hash>
//   ./test_cpp tests/vectors/invalid/bad_magic.ainf --expect-code infinity/magic
//
// INF-POLY-02: the consumer used to print the content hash without
// comparing it to the manifest, and it never ran on a hostile vector, so
// a wrong hash or a wrong refusal code passed silently. The optional
// expected-hash argument and the --expect-code hostile mode close both
// gaps; CI passes the manifest hash for full.ainf and loops the 33
// checkable invalid vectors through this binary.

#include <cstdio>
#include <cstring>

#include "active_infinity.hpp"

int main(int argc, char **argv) {
  std::string expected_hash;
  std::string expected_code;
  if (argc < 2 || argc > 4) {
    std::fprintf(stderr, "usage: %s <image.ainf> [expected-hash-hex] [--expect-code <code>]\n", argv[0]);
    return 2;
  }
  for (int index = 2; index < argc; index++) {
    if (std::strcmp(argv[index], "--expect-code") == 0) {
      if (index + 1 >= argc) {
        std::fprintf(stderr, "--expect-code needs a code\n");
        return 2;
      }
      expected_code = argv[++index];
    } else if (expected_hash.empty()) {
      expected_hash = argv[index];
    } else {
      std::fprintf(stderr, "unexpected argument: %s\n", argv[index]);
      return 2;
    }
  }
  try {
    auto image = active_infinity::Image::from_file(argv[1]);
    // INF-POLY-02: hostile mode -- the image must be refused by
    // validate_canonical with exactly the expected code.
    if (!expected_code.empty()) {
      try {
        image.validate_canonical();
        std::fprintf(stderr, "invalid image was accepted\n");
        return 1;
      } catch (const active_infinity::Error &error) {
        if (error.code() != expected_code) {
          std::fprintf(stderr, "wrong code %s, want %s\n", error.code().c_str(), expected_code.c_str());
          return 1;
        }
      }
      std::printf("PASS (refused with %s)\n", expected_code.c_str());
      return 0;
    }
    image.validate();
    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    image.validate_canonical();
    auto hash = image.content_hash_hex();
    std::printf("hash=%s\n", hash.c_str());
    // INF-POLY-02: the consumer used to print the hash without comparing
    // it to the manifest, so a wrong hash passed silently.
    if (!expected_hash.empty() && hash != expected_hash) {
      std::fprintf(stderr, "hash mismatch: %s, want %s\n", hash.c_str(), expected_hash.c_str());
      return 1;
    }
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
