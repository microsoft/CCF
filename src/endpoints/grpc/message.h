// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/serialized.h"

#include <arpa/inet.h>
#include <vector>

namespace ccf::grpc
{
  static constexpr auto TRAILER_STATUS = "grpc-status";
  static constexpr auto TRAILER_MESSAGE = "grpc-message";

  namespace impl
  {
    using CompressedFlag = uint8_t;
    using MessageLength = uint32_t;

    static constexpr size_t message_frame_length =
      sizeof(CompressedFlag) + sizeof(MessageLength);

    MessageLength read_message_frame(const uint8_t*& data, size_t& size)
    {
      auto compressed_flag = serialized::read<CompressedFlag>(data, size);
      if (compressed_flag >= 1)
      {
        throw std::logic_error(fmt::format(
          "gRPC compressed flag has unexpected value {} - currently only "
          "support "
          "unencoded gRPC payloads",
          compressed_flag));
      }
      return ntohl(serialized::read<MessageLength>(data, size));
    }

    void write_message_frame(uint8_t*& data, size_t& size, size_t message_size)
    {
      CompressedFlag compressed_flag = 0;
      serialized::write(data, size, compressed_flag);
      serialized::write(data, size, htonl(message_size));
    }
  }

  template <typename T>
  std::vector<uint8_t> make_grpc_message(T proto_data)
  {
    const auto data_length = proto_data.ByteSizeLong();
    size_t r_size = ccf::grpc::impl::message_frame_length + data_length;
    std::vector<uint8_t> msg(r_size);
    auto r_data = msg.data();

    ccf::grpc::impl::write_message_frame(r_data, r_size, data_length);

    if (!proto_data.SerializeToArray(r_data, r_size))
    {
      throw std::logic_error(fmt::format(
        "Error serialising protobuf object of type {}, size {}",
        proto_data.GetTypeName(),
        data_length));
    }
    return msg;
  }

  template <typename T>
  std::vector<uint8_t> make_grpc_messages(const std::vector<T>& proto_data)
  {
    size_t r_size = std::accumulate(
      proto_data.begin(),
      proto_data.end(),
      0,
      [](size_t current, const T& data) {
        return current + impl::message_frame_length + data.ByteSizeLong();
      });
    std::vector<uint8_t> msgs(r_size);
    auto r_data = msgs.data();

    for (const T& d : proto_data)
    {
      const auto data_length = d.ByteSizeLong();
      impl::write_message_frame(r_data, r_size, data_length);

      if (!d.SerializeToArray(r_data, r_size))
      {
        throw std::logic_error(fmt::format(
          "Error serialising protobuf object of type {}, size {}",
          d.GetTypeName(),
          data_length));
      }

      r_data += data_length;
      r_size += data_length;
    }

    return msgs;
  }
}