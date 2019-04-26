// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/serialized.h"
#include "genericserialisewrapper.h"
#include "kvtypes.h"

#include <iterator>
#include <msgpack-c/msgpack.hpp>
#include <nlohmann/json.hpp>
#include <sstream>
#include <type_traits>

MSGPACK_ADD_ENUM(kv::KvOperationType);
MSGPACK_ADD_ENUM(kv::SecurityDomain);

namespace kv
{
  class MsgPackWriter;
  template <typename W>
  class GenericSerialiseWrapper;
  using KvStoreSerialiser = GenericSerialiseWrapper<MsgPackWriter>;

  class MsgPackReader;
  template <typename W>
  class GenericDeserialiseWrapper;
  using KvStoreDeserialiser = GenericDeserialiseWrapper<MsgPackReader>;

  class MsgPackWriter
  {
  private:
    msgpack::sbuffer sb;

  public:
    template <typename T>
    void append(T&& t)
    {
      if constexpr (!std::
                      is_same_v<typename std::decay<T>::type, nlohmann::json>)
      {
        msgpack::pack(sb, std::forward<T>(t));
      }
      else
      {
        // special treatment for json
        // TODO: unnecessary copy from stringstream to sbuffer
        std::stringstream ss;
        nlohmann::json::to_msgpack(t, ss);
        const auto s = ss.str();
        sb.write(s.c_str(), s.size());
      }
    }

    void clear()
    {
      sb.clear();
    }

    bool is_empty()
    {
      return sb.size() == 0;
    }

    std::vector<uint8_t> get_raw_data()
    {
      return {reinterpret_cast<uint8_t*>(sb.data()),
              reinterpret_cast<uint8_t*>(sb.data()) + sb.size()};
    }
  };

  class MsgPackReader
  {
  public:
    const char* data_ptr;
    size_t data_offset;
    size_t data_size;
    msgpack::object_handle msg;

  public:
    MsgPackReader(const MsgPackReader& other) = delete;
    MsgPackReader& operator=(const MsgPackReader& other) = delete;

    MsgPackReader(const uint8_t* data_in_ptr = nullptr, size_t data_in_size = 0)
    {
      init(data_in_ptr, data_in_size);
    }

    void init(const uint8_t* data_in_ptr, size_t data_in_size)
    {
      data_offset = 0;
      data_ptr = (const char*)data_in_ptr;
      data_size = data_in_size;
    }

    template <typename T>
    T read_next()
    {
      msgpack::unpack(msg, data_ptr, data_size, data_offset);
      return msg->convert();
    }

    template <typename T>
    T peek_next()
    {
      auto before_offset = data_offset;
      msgpack::unpack(msg, data_ptr, data_size, data_offset);
      data_offset = before_offset;
      return msg->convert();
    }

    bool is_eos()
    {
      return data_offset >= data_size;
    }
  };

  template <>
  inline nlohmann::json MsgPackReader::read_next()
  {
    // implementation of std::streambuf to allow nlohmann::from_msgpack read
    // from data_ptr
    class ReadBuf : public std::streambuf
    {
      const std::streampos fail_pos{std::streamoff(-1)};

      std::streampos seekoff(
        std::streamoff off,
        std::ios_base::seekdir way,
        std::ios_base::openmode which) override
      {
        std::streampos sp = 0;
        switch (way)
        {
          case std::ios_base::beg:
          {
            sp = off;
            break;
          }
          case std::ios_base::cur:
          {
            sp = gptr() - eback() + off;
            break;
          }
          case std::ios_base::end:
          {
            sp = egptr() - eback() + off;
            break;
          }
          default:
            return fail_pos;
        }
        return seekpos(sp, which);
      }

      std::streampos seekpos(
        std::streampos sp, std::ios_base::openmode which) override
      {
        auto ptr = eback() + sp;
        if (ptr >= egptr() || ptr < eback())
          return fail_pos;

        setg(eback(), ptr, egptr());
        return sp;
      }

      int underflow() override
      {
        return gptr() < egptr() ? *gptr() : std::char_traits<char>::eof();
      }

    public:
      ReadBuf(const char* ptr, size_t offset, size_t size)
      {
        auto _ptr = const_cast<char*>(ptr);
        setg(_ptr, _ptr + offset, _ptr + size);
      }
    };

    ReadBuf b{data_ptr, data_offset, data_size};
    std::istream is(&b);
    const auto j = nlohmann::json::from_msgpack(is, false);
    data_offset = is.tellg();
    return j;
  }
}
