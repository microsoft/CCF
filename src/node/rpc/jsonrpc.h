// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/json.h"

#include <string>
#include <vector>

namespace jsonrpc
{
  using SeqNo = uint64_t;

  static constexpr auto RPC_VERSION = "2.0";
  static constexpr auto ID = "id";
  static constexpr auto JSON_RPC = "jsonrpc";
  static constexpr auto METHOD = "method";
  static constexpr auto READONLY = "readonly";
  static constexpr auto PARAMS = "params";
  static constexpr auto RESULT = "result";
  static constexpr auto ERR = "error";
  static constexpr auto CODE = "code";
  static constexpr auto MESSAGE = "message";
  static constexpr auto DATA = "data";
  static constexpr auto SIG = "sig";
  static constexpr auto REQ = "req";

// -32000 to -32099 are reserved for implementation-defined server-errors
#define XX_STANDARD_ERROR_CODES \
  XX(PARSE_ERROR, -32700) \
  XX(INVALID_REQUEST, -32600) \
  XX(METHOD_NOT_FOUND, -32601) \
  XX(INVALID_PARAMS, -32602) \
  XX(INTERNAL_ERROR, -32603) \
  XX(SERVER_ERROR_START, -32000) \
  XX(SERVER_ERROR_END, -32099)

#define XX_CCF_ERROR_CODES \
  XX(TX_NOT_PRIMARY, -32001) \
  XX(TX_FAILED_TO_REPLICATE, -32002) \
  XX(SCRIPT_ERROR, -32003) \
  XX(INSUFFICIENT_RIGHTS, -32004) \
  XX(TX_PRIMARY_UNKNOWN, -32005) \
  XX(RPC_NOT_SIGNED, -32006) \
  XX(INVALID_CLIENT_SIGNATURE, -32007) \
  XX(INVALID_CALLER_ID, -32008) \
  XX(CODE_ID_NOT_FOUND, -32009) \
  XX(CODE_ID_RETIRED, -32010) \
  XX(RPC_NOT_FORWARDED, -32011) \
  XX(QUOTE_NOT_VERIFIED, -32012) \
  XX(APP_ERROR_START, -32050)

  using ErrorBaseType = int;

  enum StandardErrorCodes : ErrorBaseType
  {
#define XX(Name, Value) Name = Value,
    XX_STANDARD_ERROR_CODES
#undef XX
  };

  enum CCFErrorCodes : ErrorBaseType
  {
#define XX(Name, Value) Name = Value,
    XX_CCF_ERROR_CODES
#undef XX
  };

  inline std::string get_error_prefix(ErrorBaseType ec)
  {
#define XX(Name, Value) \
  case (CCFErrorCodes::Name): \
    return "[" #Name "]: ";

    switch (CCFErrorCodes(ec))
    {
      XX_CCF_ERROR_CODES
    }
#undef XX

#define XX(Name, Value) \
  case (StandardErrorCodes::Name): \
    return "[" #Name "]: ";

    switch (StandardErrorCodes(ec))
    {
      XX_STANDARD_ERROR_CODES
    }
#undef XX

    return "";
  }

  enum class Pack
  {
    Text,
    MsgPack
  };

  inline std::vector<uint8_t> pack(const nlohmann::json& j, Pack pack)
  {
    switch (pack)
    {
      case Pack::Text:
      {
        auto s = j.dump();
        return std::vector<uint8_t>{s.begin(), s.end()};
      }

      case Pack::MsgPack:
        return nlohmann::json::to_msgpack(j);
    }

    throw std::logic_error("Invalid jsonrpc::Pack");
  }

  inline nlohmann::json unpack(const std::vector<uint8_t>& data, Pack pack)
  {
    switch (pack)
    {
      case Pack::Text:
        return nlohmann::json::parse(data);

      case Pack::MsgPack:
        return nlohmann::json::from_msgpack(data);
    }

    throw std::logic_error("Invalid jsonrpc::Pack");
  }

  inline std::optional<jsonrpc::Pack> detect_pack(
    const std::vector<uint8_t>& input)
  {
    if (input.size() == 0)
    {
      return {};
    }

    if (input[0] == '{')
    {
      return jsonrpc::Pack::Text;
    }
    else
    {
      return jsonrpc::Pack::MsgPack;
    }
  }

  //
  // Requests
  //
  struct ProcedureCallBase
  {
    std::string method;
    SeqNo id;
  };

  inline void to_json(nlohmann::json& j, const ProcedureCallBase& pc)
  {
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = pc.id;
    j[METHOD] = pc.method;
  }

  inline void from_json(const nlohmann::json& j, ProcedureCallBase& pc)
  {
    std::string jsonRpc = j[JSON_RPC];
    if (jsonRpc != RPC_VERSION)
      throw std::logic_error("Wrong JSON-RPC version: " + j.dump());
    pc.id = j[ID];
    assign_j(pc.method, j[METHOD]);
  }

  template <typename T>
  struct ProcedureCall : public ProcedureCallBase
  {
    T params = {};
  };

  template <typename T>
  void to_json(nlohmann::json& j, const ProcedureCall<T>& pc)
  {
    to_json(j, dynamic_cast<const ProcedureCallBase&>(pc));
    j[PARAMS] = pc.params;
  }

  template <typename T>
  void from_json(const nlohmann::json& j, ProcedureCall<T>& pc)
  {
    from_json(j, dynamic_cast<ProcedureCallBase&>(pc));
    pc.params = j[PARAMS];
  }

  template <>
  struct ProcedureCall<void> : public ProcedureCallBase
  {};

  template <>
  inline void to_json(nlohmann::json& j, const ProcedureCall<void>& pc)
  {
    to_json(j, dynamic_cast<const ProcedureCallBase&>(pc));
    j[PARAMS] = nlohmann::json::object();
  }

  template <>
  inline void from_json(const nlohmann::json& j, ProcedureCall<void>& pc)
  {
    from_json(j, dynamic_cast<ProcedureCallBase&>(pc));
  }

  //
  // Responses
  //
  template <typename T>
  struct Response
  {
    T result;
    SeqNo id;

    T* operator->()
    {
      return &result;
    }
  };

  template <typename T>
  void to_json(nlohmann::json& j, const Response<T>& r)
  {
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = r.id;
    j[RESULT] = r.result;
  }

  template <typename T>
  void from_json(const nlohmann::json& j, Response<T>& r)
  {
    std::string jsonRpc = j[JSON_RPC];
    if (jsonRpc != RPC_VERSION)
      throw std::logic_error("Wrong JSON-RPC version: " + j.dump());

    r.id = j[ID];
    auto search = j.find(RESULT);
    if (search == j.end())
      throw std::logic_error("No result field: " + j.dump());

    decltype(r.result) temp = *search;
    r.result = temp;
  }

  struct Error
  {
    ErrorBaseType code;
    std::string message;

    template <typename ErrorEnum>
    Error(ErrorEnum error_code, const std::string& msg = "") :
      code(static_cast<ErrorBaseType>(error_code)),
      message(get_error_prefix(code) + msg)
    {}
  };
  DECLARE_JSON_TYPE(Error)
  DECLARE_JSON_REQUIRED_FIELDS(Error, code, message)

  template <typename T>
  struct ErrorEx : public Error
  {
    T data;
  };

  template <typename T>
  void to_json(nlohmann::json& j, const ErrorEx<T>& e)
  {
    j[CODE] = e.code;
    j[MESSAGE] = e.message;
    j[DATA] = e.data;
  }

  template <typename T>
  void from_json(const nlohmann::json& j, ErrorEx<T>& e)
  {
    e.code = j[CODE];
    e.message = j[MESSAGE];
    e.data = j[DATA];
  }

  template <typename ErrorEnum>
  inline std::pair<bool, nlohmann::json> error(
    ErrorEnum error_code, const std::string msg = "")
  {
    return std::make_pair(false, Error(error_code, msg));
  }

  template <typename T>
  std::pair<bool, nlohmann::json> success(T&& result)
  {
    nlohmann::json j(result);
    return std::make_pair(true, j);
  }

  inline nlohmann::json result_response(SeqNo id, const nlohmann::json& result)
  {
    nlohmann::json j;
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = id;
    j[RESULT] = result;
    return j;
  }

  inline nlohmann::json error_response(SeqNo id, const nlohmann::json& error)
  {
    nlohmann::json j;
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = id;
    j[ERR] = error;
    return j;
  }

  template <typename ErrorEnum>
  inline nlohmann::json error_response(
    SeqNo id, ErrorEnum error_code, const std::string& msg)
  {
    nlohmann::json j;
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = id;
    j[ERR] = Error(error_code, msg);
    return j;
  }

  inline std::pair<bool, nlohmann::json> unpack_rpc(
    const std::vector<uint8_t>& input, std::optional<Pack>& o_pack)
  {
    const auto pack = detect_pack(input);
    if (!pack.has_value())
    {
      return jsonrpc::error(
        StandardErrorCodes::INVALID_REQUEST,
        "Unable to detect packing format of request");
    }

    o_pack = pack;

    nlohmann::json rpc;
    try
    {
      rpc = unpack(input, pack.value());
      if (!rpc.is_object())
      {
        return jsonrpc::error(
          StandardErrorCodes::INVALID_REQUEST,
          fmt::format("RPC payload is a not a valid object: {}", rpc.dump()));
      }
    }
    catch (const std::exception& e)
    {
      return error(
        StandardErrorCodes::INVALID_REQUEST,
        fmt::format("Exception during unpack: {}", e.what()));
    }

    return {true, rpc};
  }
}
