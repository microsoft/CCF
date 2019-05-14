#include "ds/json.h"
#include "ds/json_schema.h"

#include <array>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>

struct Foo
{
  size_t a = {};
  std::string b = {};
};
DECLARE_REQUIRED_JSON_FIELDS(Foo, a, b);

std::ostream& operator<<(std::ostream& stream, const Foo& foo)
{
  stream << "a: " << foo.a << std::endl;
  stream << "b: " << foo.b << std::endl;
  return stream;
}

struct Bar
{
  size_t a = {};
  std::string b = {};
  size_t c = {};
};
DECLARE_REQUIRED_JSON_FIELDS(Bar, a);
DECLARE_OPTIONAL_JSON_FIELDS(Bar, b, c);

std::ostream& operator<<(std::ostream& stream, const Bar& bar)
{
  stream << "a: " << bar.a << std::endl;
  stream << "b: " << bar.b << std::endl;
  stream << "c: " << bar.c << std::endl;
  return stream;
}

int main(int argc, char** argv)
{
  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    j["unused"] = "Ignored";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["c"] = 34;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;
  }

  {
    const auto foo_schema = build_schema<Foo>("Foo");
    std::cout << foo_schema.dump(2) << std::endl;
  }

  {
    const auto bar_schema = build_schema<Bar>("Bar");
    std::cout << bar_schema.dump(2) << std::endl;
  }

  return 0;
}
