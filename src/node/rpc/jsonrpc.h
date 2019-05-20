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
  static constexpr auto OK = "OK";
  static constexpr auto SIG = "sig";
  static constexpr auto REQ = "req";

#define XX_ERROR_CODES \
  XX(PARSE_ERROR, -32700) \
  XX(INVALID_REQUEST, -32600) \
  XX(METHOD_NOT_FOUND, -32601) \
  XX(INVALID_PARAMS, -32602) \
  XX(INTERNAL_ERROR, -32603) \
  XX(NODE_NOT_FOUND, -32604) \
  XX(INVALID_CLIENT_SIGNATURE, -32605) \
  XX(INVALID_CALLER_ID, -32606) \
  XX(CODE_ID_NOT_FOUND, -32607) \
  XX(CODE_ID_RETIRED, -32608) \
  XX(RPC_NOT_FORWARDED, -3269) \
  XX(SERVER_ERROR_START, -32000) \
  XX(TX_NOT_LEADER, -32001) \
  XX(TX_REPLICATED, -32002) \
  XX(TX_ROLLED_BACK, -32003) \
  XX(TX_FAILED_TO_COMMIT, -32004) \
  XX(TX_FAILED_TO_REPLICATE, -32005) \
  XX(SCRIPT_ERROR, -32006) \
  XX(INSUFFICIENT_RIGHTS, -32007) \
  XX(DENIED, -32008) \
  XX(TX_LEADER_UNKNOWN, -32009) \
  XX(SERVER_ERROR_END, -32099)

  enum ErrorCodes : int16_t
  {
#define XX(Name, Value) Name = Value,
    XX_ERROR_CODES
#undef XX
  };

  enum class Pack
  {
    Text,
    MsgPack
  };

  inline char const* get_error_prefix(int ec)
  {
    switch (ec)
    {
#define XX(Name, Value) \
  case (Name): \
    return "[" #Name "]: ";
      XX_ERROR_CODES
#undef XX
    }

    return "";
  }

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
    int code;
    std::string message;

    Error(int error_code, const std::string& msg = "") :
      code(error_code),
      message(std::string(get_error_prefix(error_code)) + msg)
    {}
  };
  ADD_JSON_TRANSLATORS(Error, code, message)

  template <typename T>
  void to_json(nlohmann::json& j, const Error& e)
  {
    j[CODE] = e.code;
    j[MESSAGE] = e.message;
  }

  template <typename T>
  void from_json(const nlohmann::json& j, Error& e)
  {
    e.code = j[CODE];
    e.message = j[MESSAGE];
  }

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

  inline std::pair<bool, nlohmann::json> error(
    int error, const std::string msg = "")
  {
    return std::make_pair(false, Error(error, msg));
  }

  template <typename T>
  std::pair<bool, nlohmann::json> success(T&& result)
  {
    nlohmann::json j(result);
    return std::make_pair(true, j);
  }

  inline std::pair<bool, nlohmann::json> success()
  {
    return success(OK);
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

  inline nlohmann::json error_response(
    SeqNo id, int error_code, const std::string& msg)
  {
    nlohmann::json j;
    j[JSON_RPC] = RPC_VERSION;
    j[ID] = id;
    j[ERR] = Error(error_code, msg);
    return j;
  }
}
