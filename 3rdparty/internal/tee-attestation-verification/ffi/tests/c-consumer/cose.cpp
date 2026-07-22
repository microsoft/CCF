// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Consumer tests for the CBOR navigation and COSE_Sign1 C ABI (tav/cose.h).

#include "support.h"

#include <cstring>

namespace {

// COSE P-256 verification-only vector, mirrored from the in-crate Rust tests.
const std::vector<uint8_t> kPhdr = {0xa1, 0x01, 0x26};
const std::string kPayload = "verification-only COSE vector";
const std::vector<uint8_t> kSpki = {
    48, 89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61,
    3, 1, 7, 3, 66, 0, 4, 201, 171, 117, 35, 159, 13, 22, 69, 184, 252, 18, 119,
    177, 246, 18, 133, 248, 151, 60, 164, 201, 112, 233, 4, 224, 54, 241, 53, 11,
    85, 3, 249, 180, 113, 248, 87, 244, 106, 253, 83, 32, 139, 158, 31, 51, 72,
    167, 32, 114, 51, 92, 109, 60, 158, 23, 216, 2, 11, 126, 11, 242, 186, 211,
    205};
const std::vector<uint8_t> kSig = {
    90, 37, 149, 163, 211, 129, 174, 167, 177, 116, 232, 19, 137, 13, 86, 18, 47,
    248, 221, 245, 81, 132, 222, 25, 6, 230, 131, 70, 41, 27, 154, 74, 57, 92,
    210, 184, 112, 104, 224, 64, 234, 0, 184, 153, 253, 249, 148, 125, 58, 93,
    103, 128, 147, 144, 252, 13, 252, 91, 233, 88, 189, 169, 103, 151};

// Append a CBOR byte string (major type 2) for buffers up to 255 bytes.
void put_bstr(std::vector<uint8_t> &out, const uint8_t *data, size_t len) {
    if (len < 24) {
        out.push_back(static_cast<uint8_t>(0x40 | len));
    } else {
        out.push_back(0x58);
        out.push_back(static_cast<uint8_t>(len));
    }
    out.insert(out.end(), data, data + len);
}

// Build a tagged (18) COSE_Sign1 envelope: [protected, {}, payload, signature].
// When embedded_payload is false the payload slot is CBOR null (detached).
std::vector<uint8_t> build_sign1(bool embedded_payload) {
    std::vector<uint8_t> env = {0xd2, 0x84};
    put_bstr(env, kPhdr.data(), kPhdr.size());
    env.push_back(0xa0); // empty map (unprotected header)
    if (embedded_payload) {
        put_bstr(env, reinterpret_cast<const uint8_t *>(kPayload.data()), kPayload.size());
    } else {
        env.push_back(0xf6); // CBOR null
    }
    put_bstr(env, kSig.data(), kSig.size());
    return env;
}

// Owns a root TavCborValue and frees it at scope exit.
struct CborRoot {
    TavCborValue *value = nullptr;
    ~CborRoot() { tav_cbor_value_free(value); }
};

} // namespace

TEST_CASE("cbor: array children are borrowed views of the owned root") {
    const uint8_t cbor[] = {0x82, 0x01, 0x42, 0xaa, 0xbb};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);
    REQUIRE(root.value != nullptr);

    const TavCborValue *child = nullptr;
    REQUIRE(tav_cbor_value_array_at(root.value, 0, &child) == nullptr);
    CHECK(tav_cbor_value_kind(child) == TAV_CBOR_KIND_INT);
    int64_t as_int = 0;
    REQUIRE(tav_cbor_value_int(child, &as_int) == nullptr);
    CHECK(as_int == 1);

    REQUIRE(tav_cbor_value_array_at(root.value, 1, &child) == nullptr);
    const uint8_t *data = nullptr;
    size_t len = 0;
    REQUIRE(tav_cbor_value_bytes(child, &data, &len) == nullptr);
    REQUIRE(len == 2);
    CHECK(data[0] == 0xaa);
    CHECK(data[1] == 0xbb);
}

TEST_CASE("cbor: failed accessors clear their out-parameters") {
    const uint8_t cbor[] = {0x82, 0x01, 0x42, 0xaa, 0xbb};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);

    const TavCborValue *int_child = nullptr;
    REQUIRE(tav_cbor_value_array_at(root.value, 0, &int_child) == nullptr);

    // Wrong type: reading bytes from an int clears the borrowed view.
    const uint8_t *data = reinterpret_cast<const uint8_t *>(0x1);
    size_t len = SIZE_MAX;
    TavError *error = tav_cbor_value_bytes(int_child, &data, &len);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(data == nullptr);
    CHECK(len == 0);
    tav_error_free(error);

    // Null handle: the scalar out-parameter is zeroed.
    int64_t scalar = INT64_MAX;
    error = tav_cbor_value_int(nullptr, &scalar);
    CHECK(tav_error_code(error) == TAV_ERROR_INVALID_ARGUMENT);
    CHECK(scalar == 0);
    tav_error_free(error);

    // Out-of-range map entry on a non-map clears both handles.
    const TavCborValue *key = reinterpret_cast<const TavCborValue *>(0x1);
    const TavCborValue *value = reinterpret_cast<const TavCborValue *>(0x1);
    error = tav_cbor_value_map_entry_at(root.value, 99, &key, &value);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(key == nullptr);
    CHECK(value == nullptr);
    tav_error_free(error);
}

TEST_CASE("cbor: map lookup and presence checks") {
    // {1: "one", "key": 42, h'aa': simple(21)}
    const uint8_t cbor[] = {0xa3, 0x01, 0x63, 'o', 'n', 'e', 0x63, 'k',
                            'e',  'y',  0x18, 0x2a, 0x41, 0xaa, 0xf5};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);

    const TavCborValue *key = nullptr;
    const TavCborValue *value = nullptr;
    REQUIRE(tav_cbor_value_map_entry_at(root.value, 0, &key, &value) == nullptr);
    const char *text = nullptr;
    size_t text_len = 0;
    REQUIRE(tav_cbor_value_text(value, &text, &text_len) == nullptr);
    CHECK(std::string(text, text_len) == "one");

    bool has_key = false;
    REQUIRE(tav_cbor_value_map_has_key(root.value, key, &has_key) == nullptr);
    CHECK(has_key);

    REQUIRE(tav_cbor_value_map_has_int_key(root.value, 2, &has_key) == nullptr);
    CHECK_FALSE(has_key);

    const char kText[] = "key";
    REQUIRE(tav_cbor_value_map_has_text_key(root.value, kText, 3, &has_key) == nullptr);
    CHECK(has_key);

    // Look up the byte-string key by handle and confirm its (simple) value.
    const TavCborValue *bstr_key = nullptr;
    REQUIRE(tav_cbor_value_map_entry_at(root.value, 2, &bstr_key, &value) == nullptr);
    REQUIRE(tav_cbor_value_map_at(root.value, bstr_key, &value) == nullptr);
    CHECK(tav_cbor_value_kind(value) == TAV_CBOR_KIND_SIMPLE);

    // A freshly parsed equivalent key still matches by structural equality.
    const uint8_t key_cbor[] = {0x41, 0xaa};
    CborRoot owned_key;
    REQUIRE(tav_cbor_value_from_bytes(key_cbor, sizeof(key_cbor), &owned_key.value) == nullptr);
    REQUIRE(tav_cbor_value_map_has_key(root.value, owned_key.value, &has_key) == nullptr);
    CHECK(has_key);

    // map_key_at / map_value_at project a single side of an entry (entry 0 is 1: "one").
    const TavCborValue *only_key = nullptr;
    const TavCborValue *only_value = nullptr;
    REQUIRE(tav_cbor_value_map_key_at(root.value, 0, &only_key) == nullptr);
    REQUIRE(tav_cbor_value_map_value_at(root.value, 0, &only_value) == nullptr);
    int64_t key_int = 0;
    REQUIRE(tav_cbor_value_int(only_key, &key_int) == nullptr);
    CHECK(key_int == 1);
    REQUIRE(tav_cbor_value_text(only_value, &text, &text_len) == nullptr);
    CHECK(std::string(text, text_len) == "one");
    // An out-of-range index fails like map_entry_at.
    CHECK(tav_cbor_value_map_key_at(root.value, 99, &only_key) != nullptr);
    CHECK(tav_cbor_value_map_value_at(root.value, 99, &only_value) != nullptr);
}

TEST_CASE("cbor: a value round-trips through to_bytes into an owned buffer") {
    const uint8_t cbor[] = {0x81, 0x01};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);

    // A non-null sentinel must be overwritten before any fallible work.
    TavByteBuffer *bytes = reinterpret_cast<TavByteBuffer *>(0x1);
    REQUIRE(tav_cbor_value_to_bytes(root.value, &bytes) == nullptr);
    REQUIRE(bytes != nullptr);
    REQUIRE(tav_byte_buffer_len(bytes) == sizeof(cbor));
    CHECK(std::memcmp(tav_byte_buffer_data(bytes), cbor, sizeof(cbor)) == 0);

    tav_byte_buffer_free(bytes);
}

TEST_CASE("cbor: len reports array and map element counts") {
    // Array of two elements: [1, h'aabb'].
    const uint8_t arr[] = {0x82, 0x01, 0x42, 0xaa, 0xbb};
    CborRoot array_root;
    REQUIRE(tav_cbor_value_from_bytes(arr, sizeof(arr), &array_root.value) == nullptr);
    size_t len = SIZE_MAX;
    REQUIRE(tav_cbor_value_len(array_root.value, &len) == nullptr);
    CHECK(len == 2);

    // Map of three entries: {1: "one", "key": 42, h'aa': simple(21)}.
    const uint8_t map[] = {0xa3, 0x01, 0x63, 'o', 'n', 'e', 0x63, 'k',
                           'e',  'y',  0x18, 0x2a, 0x41, 0xaa, 0xf5};
    CborRoot map_root;
    REQUIRE(tav_cbor_value_from_bytes(map, sizeof(map), &map_root.value) == nullptr);
    len = SIZE_MAX;
    REQUIRE(tav_cbor_value_len(map_root.value, &len) == nullptr);
    CHECK(len == 3);

    // len() is undefined for scalars: the error clears the out-parameter.
    const TavCborValue *scalar = nullptr;
    REQUIRE(tav_cbor_value_array_at(array_root.value, 0, &scalar) == nullptr);
    len = SIZE_MAX;
    TavError *error = tav_cbor_value_len(scalar, &len);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_CBOR);
    CHECK(len == 0);
    tav_error_free(error);
}

TEST_CASE("cbor: typed map lookups by int and text key") {
    // {1: "one", "key": 42, h'aa': simple(21)}
    const uint8_t cbor[] = {0xa3, 0x01, 0x63, 'o', 'n', 'e', 0x63, 'k',
                            'e',  'y',  0x18, 0x2a, 0x41, 0xaa, 0xf5};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);

    // Integer key lookup returns the text value.
    const TavCborValue *value = nullptr;
    REQUIRE(tav_cbor_value_map_at_int(root.value, 1, &value) == nullptr);
    const char *text = nullptr;
    size_t text_len = 0;
    REQUIRE(tav_cbor_value_text(value, &text, &text_len) == nullptr);
    CHECK(std::string(text, text_len) == "one");

    // Text key lookup returns the int value.
    const char kKey[] = "key";
    REQUIRE(tav_cbor_value_map_at_text(root.value, kKey, 3, &value) == nullptr);
    int64_t as_int = 0;
    REQUIRE(tav_cbor_value_int(value, &as_int) == nullptr);
    CHECK(as_int == 42);

    // Absent keys report an error and clear the borrowed handle.
    value = reinterpret_cast<const TavCborValue *>(0x1);
    TavError *error = tav_cbor_value_map_at_int(root.value, 2, &value);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_CBOR);
    CHECK(value == nullptr);
    tav_error_free(error);

    value = reinterpret_cast<const TavCborValue *>(0x1);
    const char kMissing[] = "nope";
    error = tav_cbor_value_map_at_text(root.value, kMissing, 4, &value);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_CBOR);
    CHECK(value == nullptr);
    tav_error_free(error);
}

TEST_CASE("cbor: simple value extraction") {
    // CBOR simple value 21 (encoded as 0xf5); this library models booleans and
    // nil as CBOR simple values (20/21/22).
    const uint8_t cbor[] = {0xf5};
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(cbor, sizeof(cbor), &root.value) == nullptr);
    CHECK(tav_cbor_value_kind(root.value) == TAV_CBOR_KIND_SIMPLE);

    uint8_t simple = 0;
    REQUIRE(tav_cbor_value_simple(root.value, &simple) == nullptr);
    CHECK(simple == 21);

    // Reading a simple value from a non-simple value fails and zeroes the out.
    const uint8_t int_cbor[] = {0x01};
    CborRoot int_root;
    REQUIRE(tav_cbor_value_from_bytes(int_cbor, sizeof(int_cbor), &int_root.value) == nullptr);
    simple = 0xff;
    TavError *error = tav_cbor_value_simple(int_root.value, &simple);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(simple == 0);
    tav_error_free(error);
}

TEST_CASE("cbor: tag number and tagged payload") {
    // A COSE_Sign1 envelope is tag(18) wrapping the 4-element array.
    std::vector<uint8_t> env = build_sign1(/*embedded_payload=*/true);
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(env.data(), env.size(), &root.value) == nullptr);
    CHECK(tav_cbor_value_kind(root.value) == TAV_CBOR_KIND_TAGGED);

    uint64_t tag = 0;
    REQUIRE(tav_cbor_value_tag(root.value, &tag) == nullptr);
    CHECK(tag == TAV_COSE_TAG_SIGN1);

    const TavCborValue *payload = nullptr;
    REQUIRE(tav_cbor_value_tagged_payload(root.value, &payload) == nullptr);
    REQUIRE(payload != nullptr);
    CHECK(tav_cbor_value_kind(payload) == TAV_CBOR_KIND_ARRAY);
    size_t payload_len = 0;
    REQUIRE(tav_cbor_value_len(payload, &payload_len) == nullptr);
    CHECK(payload_len == 4);

    // The inner array is not tagged: both tag accessors fail and clear outs.
    uint64_t not_tag = 7;
    TavError *error = tav_cbor_value_tag(payload, &not_tag);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(not_tag == 0);
    tav_error_free(error);

    const TavCborValue *no_payload = reinterpret_cast<const TavCborValue *>(0x1);
    error = tav_cbor_value_tagged_payload(payload, &no_payload);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(no_payload == nullptr);
    tav_error_free(error);
}

TEST_CASE("cose: embedded COSE_Sign1 verification succeeds") {
    std::vector<uint8_t> env = build_sign1(/*embedded_payload=*/true);
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(env.data(), env.size(), &root.value) == nullptr);

    const TavCborValue *sign1 = nullptr;
    REQUIRE(tav_validate_cose_sign1(root.value, &sign1) == nullptr);
    REQUIRE(sign1 != nullptr);
    CHECK(tav_cbor_value_kind(sign1) == TAV_CBOR_KIND_ARRAY);

    TavError *error = tav_verify_cose_sign1_embedded(
        sign1, kSpki.data(), kSpki.size(), TAV_COSE_ALG_ES256);
    CHECK(error == nullptr);
    tav_error_free(error);
}

TEST_CASE("cose: embedded verification rejects a tampered signature") {
    std::vector<uint8_t> env = build_sign1(/*embedded_payload=*/true);
    env.back() ^= 0xff; // corrupt the trailing signature byte
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(env.data(), env.size(), &root.value) == nullptr);

    const TavCborValue *sign1 = nullptr;
    REQUIRE(tav_validate_cose_sign1(root.value, &sign1) == nullptr);

    // A verifier that skipped the signature check would wrongly return success.
    TavError *error = tav_verify_cose_sign1_embedded(
        sign1, kSpki.data(), kSpki.size(), TAV_COSE_ALG_ES256);
    REQUIRE(error != nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_VERIFICATION);
    tav_error_free(error);
}

TEST_CASE("cose: detached verification rejects an embedded payload") {
    std::vector<uint8_t> env = build_sign1(/*embedded_payload=*/true);
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(env.data(), env.size(), &root.value) == nullptr);

    const TavCborValue *sign1 = nullptr;
    REQUIRE(tav_validate_cose_sign1(root.value, &sign1) == nullptr);

    TavError *error = tav_verify_cose_sign1_detached(
        sign1, reinterpret_cast<const uint8_t *>(kPayload.data()), kPayload.size(),
        kSpki.data(), kSpki.size(), TAV_COSE_ALG_ES256);
    REQUIRE(error != nullptr);
    CHECK(tav_error_code(error) == TAV_ERROR_COSE_UNEXPECTED_TYPE);
    CHECK(std::string(tav_error_message(error)).find("requires nil COSE payload") !=
          std::string::npos);
    tav_error_free(error);
}

TEST_CASE("cose: detached verification accepts a nil payload") {
    std::vector<uint8_t> env = build_sign1(/*embedded_payload=*/false);
    CborRoot root;
    REQUIRE(tav_cbor_value_from_bytes(env.data(), env.size(), &root.value) == nullptr);

    const TavCborValue *sign1 = nullptr;
    REQUIRE(tav_validate_cose_sign1(root.value, &sign1) == nullptr);

    TavError *error = tav_verify_cose_sign1_detached(
        sign1, reinterpret_cast<const uint8_t *>(kPayload.data()), kPayload.size(),
        kSpki.data(), kSpki.size(), TAV_COSE_ALG_ES256);
    CHECK(error == nullptr);
    tav_error_free(error);
}
