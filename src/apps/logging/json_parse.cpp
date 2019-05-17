#include "ds/json.h"
#include "ds/json_schema.h"

#include <array>
#include <iostream>
#include <nlohmann/json.hpp>
#include <vector>

namespace ccf
{
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

  struct Baz : public Bar
  {
    size_t d = {};
    size_t e = {};
  };
  DECLARE_REQUIRED_JSON_FIELDS_WITH_BASE(Baz, Bar, d);
  DECLARE_OPTIONAL_JSON_FIELDS_WITH_BASE(Baz, Bar, e);

  std::ostream& operator<<(std::ostream& stream, const Bar& bar)
  {
    stream << "a: " << bar.a << std::endl;
    stream << "b: " << bar.b << std::endl;
    stream << "c: " << bar.c << std::endl;
    return stream;
  }

  struct Buzz
  {
    std::optional<size_t> a = std::nullopt;
    std::optional<size_t> b = 2;
  };
  DECLARE_REQUIRED_JSON_FIELDS(Buzz);
  DECLARE_OPTIONAL_JSON_FIELDS(Buzz, a, b);

  std::ostream& operator<<(std::ostream& stream, const Buzz& buzz)
  {
    stream << "a: ";
    if (buzz.a.has_value())
      stream << buzz.a.value();
    else
      stream << "EMPTY";
    stream << std::endl;

    stream << "b: ";
    if (buzz.b.has_value())
      stream << buzz.b.value();
    else
      stream << "EMPTY";
    stream << std::endl;
    return stream;
  }
}

using namespace ccf;

int main(int argc, char** argv)
{
  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;

    nlohmann::json j2 = foo;
    std::cout << j2.dump(2) << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    j["unused"] = "Ignored";
    const Foo foo = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << foo << std::endl;

    nlohmann::json j2 = foo;
    std::cout << j2.dump(2) << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;

    nlohmann::json j2 = bar;
    std::cout << j2.dump(2) << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["b"] = "Hello";
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;

    nlohmann::json j2 = bar;
    std::cout << j2.dump(2) << std::endl;
  }

  {
    nlohmann::json j;
    j["a"] = 12;
    j["c"] = 34;
    const Bar bar = j;

    std::cout << j.dump(2) << std::endl;
    std::cout << bar << std::endl;

    nlohmann::json j2 = bar;
    std::cout << j2.dump(2) << std::endl;

    {
      j["d"] = 56;
      const Baz baz = j;
      nlohmann::json j3 = baz;
      std::cout << j3.dump(2) << std::endl;
    }
  }

  {
    nlohmann::json j = nlohmann::json::object();
    std::cout << j.dump(2) << std::endl;
    std::cout << j.get<Buzz>() << std::endl;

    j["a"] = 5;
    std::cout << j.dump(2) << std::endl;
    std::cout << j.get<Buzz>() << std::endl;

    j["b"] = 3;
    std::cout << j.dump(2) << std::endl;
    std::cout << j.get<Buzz>() << std::endl;

    Buzz buzz;
    std::cout << buzz << std::endl;
    nlohmann::json j2 = buzz;
    std::cout << j2 << std::endl;

    buzz.a = 42;
    std::cout << buzz << std::endl;
    nlohmann::json j3 = buzz;
    std::cout << j3 << std::endl;
  }

  {
    const auto foo_schema = build_schema<Foo>("Foo");
    std::cout << foo_schema.dump(2) << std::endl;
  }

  {
    const auto bar_schema = build_schema<Bar>("Bar");
    std::cout << bar_schema.dump(2) << std::endl;
  }

  {
    const auto baz_schema = build_schema<Baz>("Baz");
    std::cout << baz_schema.dump(2) << std::endl;
  }

  {
    const auto buzz_schema = build_schema<Buzz>("Buzz");
    std::cout << buzz_schema.dump(2) << std::endl;
  }

  return 0;
}
