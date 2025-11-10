// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "ccf/crypto/cose.h"

#include "crypto/openssl/cose_sign.h"
#include "crypto/openssl/cose_verifier.h"

#include <cstdint>
#include <doctest/doctest.h>
#include <fstream>
#include <limits>
#include <qcbor/qcbor_decode.h>
#include <qcbor/qcbor_spiffy_decode.h>
#include <string>
#include <vector>

static const std::vector<int64_t> keys = {
  42, std::numeric_limits<int64_t>::min(), std::numeric_limits<int64_t>::max()};

static const std::vector<ccf::cose::edit::pos::Type> positions = {
  ccf::cose::edit::pos::AtKey{42},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::min()},
  ccf::cose::edit::pos::AtKey{std::numeric_limits<int64_t>::max()},
  ccf::cose::edit::pos::InArray{}};

const std::vector<uint8_t> value = {1, 2, 3, 4};

enum class PayloadType
{
  Detached,
  Flat,
  NestedCBOR // Useful to test the payload transfer
};

struct Signer
{
  ccf::crypto::KeyPair_OpenSSL kp;
  std::vector<uint8_t> payload;
  bool detached_payload = false;

  Signer(PayloadType type) : kp(ccf::crypto::CurveID::SECP384R1)
  {
    switch (type)
    {
      case PayloadType::Detached:
        detached_payload = true;
        payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        break;
      case PayloadType::Flat:
        payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
        break;
      case PayloadType::NestedCBOR:
      {
        payload.resize(1024);
        QCBOREncodeContext ctx;
        QCBOREncode_Init(&ctx, {payload.data(), payload.size()});
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddInt64(&ctx, 1);
        QCBOREncode_OpenArray(&ctx);
        QCBOREncode_AddInt64(&ctx, 2);
        QCBOREncode_AddInt64(&ctx, 3);
        QCBOREncode_CloseArray(&ctx);
        QCBOREncode_CloseArray(&ctx);
        UsefulBufC result;
        QCBOREncode_Finish(&ctx, &result);
        payload.resize(result.len);
        payload.shrink_to_fit();
      }
      break;
    }
  }

  std::vector<uint8_t> make_cose_sign1()
  {
    const auto pheaders = {
      ccf::crypto::cose_params_int_bytes(300, value),
      ccf::crypto::cose_params_int_int(301, 34)};

    return ccf::crypto::cose_sign1(kp, pheaders, payload, detached_payload);
  };

  void verify(const std::vector<uint8_t>& cose_sign1)
  {
    auto verifier =
      ccf::crypto::make_cose_verifier_from_key(kp.public_key_pem());
    if (detached_payload)
    {
      REQUIRE(verifier->verify_detached(cose_sign1, payload));
    }
    else
    {
      std::span<uint8_t> payload_;
      REQUIRE(verifier->verify(cose_sign1, payload_));
      std::vector<uint8_t> payload_copy(payload_.begin(), payload_.end());
      REQUIRE(payload == payload_copy);
    }
  };
};

TEST_CASE("Verification and payload invariant")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();
    signer.verify(csp);

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set = ccf::cose::edit::set_unprotected_header(csp, desc);

        signer.verify(csp_set);
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});
      signer.verify(csp_set_empty);
    }
  }
}

TEST_CASE("Idempotence")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set_once = ccf::cose::edit::set_unprotected_header(csp, desc);

        auto csp_set_twice =
          ccf::cose::edit::set_unprotected_header(csp_set_once, desc);
        REQUIRE(csp_set_once == csp_set_twice);
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});
      auto csp_set_twice_empty = ccf::cose::edit::set_unprotected_header(
        csp_set_empty, ccf::cose::edit::desc::Empty{});

      REQUIRE(csp_set_empty == csp_set_twice_empty);
    }
  }
}

TEST_CASE("Check unprotected header")
{
  for (auto type :
       {PayloadType::Detached, PayloadType::Flat, PayloadType::NestedCBOR})
  {
    Signer signer(type);
    auto csp = signer.make_cose_sign1();

    for (const auto& key : keys)
    {
      for (const auto& position : positions)
      {
        ccf::cose::edit::desc::Value desc{position, key, value};
        auto csp_set = ccf::cose::edit::set_unprotected_header(csp, desc);

        std::vector<uint8_t> ref(1024);
        {
          // Create expected reference value for the unprotected header
          UsefulBuf ref_buf{ref.data(), ref.size()};
          QCBOREncodeContext ctx;
          QCBOREncode_Init(&ctx, ref_buf);
          QCBOREncode_OpenMap(&ctx);

          if (std::holds_alternative<ccf::cose::edit::pos::InArray>(position))
          {
            QCBOREncode_OpenArrayInMapN(&ctx, key);
            QCBOREncode_AddBytes(&ctx, {value.data(), value.size()});
            QCBOREncode_CloseArray(&ctx);
          }
          else if (std::holds_alternative<ccf::cose::edit::pos::AtKey>(
                     position))
          {
            QCBOREncode_OpenMapInMapN(&ctx, key);
            auto subkey = std::get<ccf::cose::edit::pos::AtKey>(position).key;
            QCBOREncode_OpenArrayInMapN(&ctx, subkey);
            QCBOREncode_AddBytes(&ctx, {value.data(), value.size()});
            QCBOREncode_CloseArray(&ctx);
            QCBOREncode_CloseMap(&ctx);
          }
          QCBOREncode_CloseMap(&ctx);
          UsefulBufC ref_buf_c;
          QCBOREncode_Finish(&ctx, &ref_buf_c);
          ref.resize(ref_buf_c.len);
          ref.shrink_to_fit();
        }

        size_t uhdr_start, uhdr_end;
        QCBORError err;
        QCBORItem item;
        QCBORDecodeContext ctx;
        UsefulBufC buf{csp_set.data(), csp_set.size()};
        QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterArray(&ctx, nullptr);
        QCBORDecode_GetNthTagOfLast(&ctx, 0);
        // Protected header
        QCBORDecode_VGetNextConsume(&ctx, &item);
        // Unprotected header
        QCBORDecode_PartialFinish(&ctx, &uhdr_start);
        QCBORDecode_VGetNextConsume(&ctx, &item);
        QCBORDecode_PartialFinish(&ctx, &uhdr_end);
        std::vector<uint8_t> uhdr{
          csp_set.data() + uhdr_start, csp_set.data() + uhdr_end};
        REQUIRE(uhdr == ref);
        // Payload
        QCBORDecode_VGetNextConsume(&ctx, &item);
        // Signature
        QCBORDecode_VGetNextConsume(&ctx, &item);
        QCBORDecode_ExitArray(&ctx);
        err = QCBORDecode_Finish(&ctx);
        REQUIRE(err == QCBOR_SUCCESS);
      }
    }

    {
      auto csp_set_empty = ccf::cose::edit::set_unprotected_header(
        csp, ccf::cose::edit::desc::Empty{});

      std::vector<uint8_t> ref(1024);
      {
        // Create expected reference value for the unprotected header
        UsefulBuf ref_buf{ref.data(), ref.size()};
        QCBOREncodeContext ctx;
        QCBOREncode_Init(&ctx, ref_buf);
        QCBOREncode_OpenMap(&ctx);
        QCBOREncode_CloseMap(&ctx);
        UsefulBufC ref_buf_c;
        QCBOREncode_Finish(&ctx, &ref_buf_c);
        ref.resize(ref_buf_c.len);
        ref.shrink_to_fit();
      }

      size_t uhdr_start, uhdr_end;
      QCBORError err;
      QCBORItem item;
      QCBORDecodeContext ctx;
      UsefulBufC buf{csp_set_empty.data(), csp_set_empty.size()};
      QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);
      QCBORDecode_EnterArray(&ctx, nullptr);
      QCBORDecode_GetNthTagOfLast(&ctx, 0);
      // Protected header
      QCBORDecode_VGetNextConsume(&ctx, &item);
      // Unprotected header
      QCBORDecode_PartialFinish(&ctx, &uhdr_start);
      QCBORDecode_VGetNextConsume(&ctx, &item);
      QCBORDecode_PartialFinish(&ctx, &uhdr_end);
      std::vector<uint8_t> uhdr{
        csp_set_empty.data() + uhdr_start, csp_set_empty.data() + uhdr_end};
      REQUIRE(uhdr == ref);
      // Payload
      QCBORDecode_VGetNextConsume(&ctx, &item);
      // Signature
      QCBORDecode_VGetNextConsume(&ctx, &item);
      QCBORDecode_ExitArray(&ctx);
      err = QCBORDecode_Finish(&ctx);
    }
  }
}