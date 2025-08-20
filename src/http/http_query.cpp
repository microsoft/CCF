// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/http_query.h"
#include "http/http_parser.h"

#include <cctype>
#include <vector>

namespace ccf::http
{
  ParsedQuery parse_query(const std::string_view& query)
  {
    ParsedQuery parsed;
    
    // Find parameter boundaries by looking for unescaped '&' characters
    std::vector<std::string_view> params;
    size_t start = 0;
    size_t pos = 0;
    
    while (pos < query.length())
    {
      if (query[pos] == '%' && pos + 2 < query.length() && 
          std::isxdigit(query[pos + 1]) && std::isxdigit(query[pos + 2]))
      {
        // Skip URL-encoded sequence
        pos += 3;
      }
      else if (query[pos] == '&')
      {
        // Found parameter separator - always add the parameter, even if empty
        params.push_back(query.substr(start, pos - start));
        start = pos + 1;
        pos = start;
      }
      else
      {
        pos++;
      }
    }
    
    // Add the last parameter
    if (start <= query.length())  // Use <= instead of < to handle trailing &
    {
      params.push_back(query.substr(start));
    }
    
    // Parse each parameter 
    for (const auto& param : params)
    {
      // Don't skip empty params - they should create entries with empty keys
      
      // Find the first unescaped '=' character
      size_t eq_pos = std::string_view::npos;
      size_t i = 0;
      while (i < param.length())
      {
        if (param[i] == '%' && i + 2 < param.length() &&
            std::isxdigit(param[i + 1]) && std::isxdigit(param[i + 2]))
        {
          // Skip URL-encoded sequence
          i += 3;
        }
        else if (param[i] == '=' && eq_pos == std::string_view::npos)
        {
          // Found the first unescaped equals sign
          eq_pos = i;
          break;
        }
        else
        {
          i++;
        }
      }
      
      std::string_view encoded_key, encoded_value;
      if (eq_pos != std::string_view::npos)
      {
        encoded_key = param.substr(0, eq_pos);
        encoded_value = param.substr(eq_pos + 1);
      }
      else
      {
        // No '=' found, treat entire param as key with empty value
        encoded_key = param;
        encoded_value = "";
      }
      
      // URL-decode the key and value
      std::string decoded_key = http::url_decode(encoded_key);
      std::string decoded_value = http::url_decode(encoded_value);
      
      parsed.emplace(std::move(decoded_key), std::move(decoded_value));
    }

    return parsed;
  }
}