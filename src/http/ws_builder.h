// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/serialized.h"
#include "../kv/kv_types.h"
#include "ws_parser.h"

#include <arpa/inet.h>

namespace ws
{
  static std::vector<uint8_t> make_frame(size_t frame_size)
  {
    size_t sz_size = 0;
    if (frame_size > 125)
    {
      sz_size = frame_size > std::numeric_limits<uint16_t>::max() ? 8 : 2;
    }

    size_t ws_h_size = ws::INITIAL_READ + sz_size;
    std::vector<uint8_t> msg(ws_h_size + frame_size);
    msg[0] = 0x82;
    switch (sz_size)
    {
      case 0:
      {
        msg[1] = frame_size;
        break;
      }
      case 2:
      {
        msg[1] = 0x7e;
        *((uint16_t*)&msg[2]) = htons(frame_size);
        break;
      }
      case 8:
      {
        msg[1] = 0x7f;
        *((uint64_t*)&msg[2]) = htobe64(frame_size);
        break;
      }
      default:
        throw std::logic_error(fmt::format("Invalid sz_size: {}", sz_size));
    }

    return msg;
  };

  static std::vector<uint8_t> make_in_frame(
    const std::string& path, const std::vector<uint8_t>& body)
  {
    size_t in_frame_size = ws::in_header_size(path) + body.size();
    auto frame = make_frame(in_frame_size);
    size_t ws_h_size = frame.size() - in_frame_size;

    uint8_t* p = frame.data() + ws_h_size;
    size_t s = frame.size() - ws_h_size;
    serialized::write_lps(p, s, path);
    assert(s == body.size());
    ::memcpy(p, body.data(), s);
    return frame;
  }

  static std::vector<uint8_t> make_out_frame(
    size_t code,
    kv::Version seqno,
    kv::Consensus::View view,
    kv::Version global_commit,
    const std::vector<uint8_t>& body)
  {
    size_t out_frame_size = ws::OUT_CCF_HEADER_SIZE + body.size();
    auto frame = make_frame(out_frame_size);
    size_t ws_h_size = frame.size() - out_frame_size;

    uint8_t* p = frame.data() + ws_h_size;
    size_t s = frame.size() - ws_h_size;
    serialized::write<uint16_t>(p, s, code);
    serialized::write<size_t>(p, s, seqno);
    serialized::write<size_t>(p, s, view);
    serialized::write<size_t>(p, s, global_commit);
    assert(s == body.size());
    ::memcpy(p, body.data(), s);
    return frame;
  }
}