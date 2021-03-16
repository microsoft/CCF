// TODO: Delete this file

#pragma once

#include <stdexcept>

class UrlQueryParseError : public std::invalid_argument
{
public:
  using std::invalid_argument::invalid_argument;
};
