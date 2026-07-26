// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Shared helpers for the C ABI consumer tests. Each translation unit includes
// this header plus doctest, and contributes TEST_CASEs for one API surface.

#pragma once

#include "doctest.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
#include "tav/caci.h"
#include "tav/cose.h"
#include "tav/snp.h"
#include "tav/utils.h"
}

#ifndef TAV_REPO_ROOT
#error "TAV_REPO_ROOT must be defined by the build system"
#endif

namespace tav_test {

// Mirrors c_ffi::utils::MAX_INPUT_LEN (1 GiB); not exported by the headers.
constexpr size_t kMaxInputLen = 1024ull * 1024ull * 1024ull;

inline std::vector<uint8_t> read_file(const std::string &relative) {
    std::string path = std::string(TAV_REPO_ROOT) + "/" + relative;
    FILE *file = std::fopen(path.c_str(), "rb");
    REQUIRE_MESSAGE(file != nullptr, "failed to open fixture: " << path);
    std::fseek(file, 0, SEEK_END);
    long size = std::ftell(file);
    REQUIRE(size >= 0);
    std::rewind(file);
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    if (size > 0) {
        REQUIRE(std::fread(bytes.data(), 1, bytes.size(), file) == bytes.size());
    }
    std::fclose(file);
    return bytes;
}

// Fixture decoders below throw on malformed input rather than registering a
// doctest assertion per byte (the PEM/JSON fixtures are large enough that
// per-byte REQUIREs would dwarf the real assertion count). An uncaught
// exception is still reported by doctest as a failing test.
[[noreturn]] inline void fixture_error(const std::string &message) {
    throw std::runtime_error(message);
}

inline int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

inline std::vector<uint8_t> hex_decode(const std::vector<uint8_t> &text) {
    std::vector<uint8_t> out;
    int high = -1;
    for (uint8_t raw : text) {
        char ch = static_cast<char>(raw);
        if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') continue;
        int nibble = hex_nibble(ch);
        if (nibble < 0) fixture_error("non-hex character in fixture");
        if (high < 0) {
            high = nibble;
        } else {
            out.push_back(static_cast<uint8_t>((high << 4) | nibble));
            high = -1;
        }
    }
    if (high >= 0) fixture_error("odd number of hex digits in fixture");
    return out;
}

// Encode bytes as lowercase hex, e.g. to compare a fixed-size report field
// against a checked-in golden value.
inline std::string hex_encode(const uint8_t *data, size_t len) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

inline int base64_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

inline std::vector<uint8_t> base64_decode(const std::vector<uint8_t> &text) {
    std::vector<uint8_t> out;
    unsigned int accumulator = 0;
    int bits = -8;
    for (uint8_t raw : text) {
        char ch = static_cast<char>(raw);
        if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') continue;
        if (ch == '=') break;
        int value = base64_value(ch);
        if (value < 0) fixture_error("non-base64 character in fixture");
        accumulator = (accumulator << 6) | static_cast<unsigned int>(value);
        bits += 6;
        if (bits >= 0) {
            out.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xff));
            bits -= 8;
        }
    }
    return out;
}

// Minimal JSON string-field extractor for the compact (no inter-token
// whitespace) host AMD certificate bundle fixture. Only the `\n` escape needs
// translating back to a literal newline; every other character is copied
// through unchanged.
// Note: this is not a general-purpose JSON parser, and it will fail on nested input
inline std::string json_string_field(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\":\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos) fixture_error("JSON missing string field: " + key);
    pos += needle.size();

    std::string out;
    for (; pos < json.size(); pos++) {
        if (json[pos] == '"') return out;
        if (json[pos] == '\\' && pos + 1 < json.size() && json[pos + 1] == 'n') {
            out.push_back('\n');
            pos++;
        } else {
            out.push_back(json[pos]);
        }
    }
    fixture_error("unterminated JSON string for key: " + key);
}

inline std::string to_string(const std::vector<uint8_t> &bytes) {
    return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
}

} // namespace tav_test
