// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "handlerregistry.h"
#include "http/http_consts.h"

#include <http-parser/http_parser.h>
#include <set>

namespace ccf
{
  static HandleFunction restrict_verbs_adapter(
    const HandleFunction& f, const std::set<http_method>& allowed_verbs)
  {
    return [f, allowed_verbs](RequestArgs& args) {
      const auto verb = (http_method)args.rpc_ctx->get_request_verb();
      if (allowed_verbs.find(verb) == allowed_verbs.end())
      {
        args.rpc_ctx->set_response_status(HTTP_STATUS_METHOD_NOT_ALLOWED);
        std::string allow_header_value;
        for (auto it = allowed_verbs.begin(); it != allowed_verbs.end(); ++it)
        {
          allow_header_value += fmt::format(
            "{}{}",
            (it == allowed_verbs.begin() ? "" : ", "),
            http_method_str(*it));
        }
        args.rpc_ctx->set_response_header(
          http::headers::ALLOW, allow_header_value);
        return;
      }

      f(args);
    };
  }

  static HandleFunction get_only_adapter(const HandleFunction& f)
  {
      return restrict_verbs_adapter(f, {HTTP_GET});
  }

  static HandleFunction post_only_adapter(const HandleFunction& f)
  {
      return restrict_verbs_adapter(f, {HTTP_POST});
  }
}