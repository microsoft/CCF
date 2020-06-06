#pragma once

#include "../3rdparty/backward-cpp/backward.hpp"
#include "logger.h"

#include <exception>
#include <string>

namespace ccf
{
  class ccf_logic_error : public std::exception
  {
  public:
    ccf_logic_error(const std::string& what_arg)
    {
      backward::StackTrace st;
      st.load_here();

      std::ostringstream stream;
      backward::Printer p;
      p.print(st, stream);

      if (!what_arg.empty())
      {
        result.append(what_arg.c_str());
        result.append("\n");
      }
      result.append(stream.str());
    }

    ccf_logic_error() : ccf_logic_error("") {}

    const char* what() const throw() override
    {
      return result.c_str();
    }

  private:
    std::string result;
  };
};