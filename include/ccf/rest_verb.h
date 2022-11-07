// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/hash.h"

#include <llhttp/llhttp.h>
#include <string>

namespace ccf
{
  static inline llhttp_method http_method_from_str(const std::string_view& s)
  {
    const auto hashed_name = ds::fnv_1a<size_t>(s);

#define XX(num, name, string) \
  case (ds::fnv_1a<size_t>(#string)): \
  { \
    return llhttp_method(num); \
  }

    switch (hashed_name)
    {
      HTTP_METHOD_MAP(XX)

      default:
      {
        throw std::logic_error(fmt::format("Unknown HTTP method '{}'", s));
      }
    }
#undef XX
  }

  /*!
    Extension of llhttp_method
    to allow make_*_endpoint() to be a single uniform interface to define
    handlers for more than just HTTP verbs. Formerly used to allow WebSockets
    handlers, now removed. Kept for potential future extensions.

    This may be removed if instead of exposing a single RpcContext, callbacks
    are instead given a specialised *RpcContext, and make_endpoint becomes
    templated on Verb and specialised on the respective enum types.
  */
  class RESTVerb
  {
  private:
    int verb;

  public:
    RESTVerb() : verb(std::numeric_limits<int>::min()) {}
    RESTVerb(const llhttp_method& hm) : verb(hm) {}
    RESTVerb(const std::string& s)
    {
      verb = http_method_from_str(s.c_str());
    }

    std::optional<llhttp_method> get_http_method() const
    {
      return static_cast<llhttp_method>(verb);
    }

    const char* c_str() const
    {
      return llhttp_method_name(static_cast<llhttp_method>(verb));
    }

    bool operator<(const RESTVerb& o) const
    {
      return verb < o.verb;
    }

    bool operator==(const RESTVerb& o) const
    {
      return verb == o.verb;
    }

    bool operator!=(const RESTVerb& o) const
    {
      return !(*this == o);
    }
  };

  // Custom to_json and from_json specializations which encode RESTVerb in a
  // lower-cased string, so it can be used in OpenAPI and similar documents
  inline void to_json(nlohmann::json& j, const RESTVerb& verb)
  {
    std::string s(verb.c_str());
    nonstd::to_lower(s);
    j = s;
  }

  inline void from_json(const nlohmann::json& j, RESTVerb& verb)
  {
    if (!j.is_string())
    {
      throw std::runtime_error(fmt::format(
        "Cannot parse RESTVerb from non-string JSON value: {}", j.dump()));
    }

    std::string s = j.get<std::string>();
    nonstd::to_upper(s);

    verb = RESTVerb(s.c_str());
  }
}
