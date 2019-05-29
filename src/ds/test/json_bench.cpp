// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#define PICOBENCH_IMPLEMENT_WITH_MAIN
#include "../json.h"

#include <picobench/picobench.hpp>

template <class A>
inline void do_not_optimize(A const& value)
{
  asm volatile("" : : "r,m"(value) : "memory");
}

inline void clobber_memory()
{
  asm volatile("" : : : "memory");
}

struct Simple
{
  size_t x;
  int y;
};

void to_json(nlohmann::json& j, const Simple& s)
{
  j["x"] = s.x;
  j["y"] = s.y;
}

void from_json(const nlohmann::json& j, Simple& s)
{
  s.x = j["x"];
  s.y = j["y"];
}

struct Complex
{
  struct Foo
  {
    size_t n;
    std::string s;
  };

  struct Bar
  {
    size_t a;
    size_t b;
    std::vector<Foo> foos;
  };

  bool b;
  int i;
  std::string s;
  std::map<size_t, Bar> m;
};

static void roundtrip_simple(picobench::state& s)
{
  Simple a;
  picobench::scope scope(s);
  for (size_t i = 0; i < s.iterations(); ++i)
  {
    nlohmann::json j = a;
    const auto b = j.get<Simple>();
    do_not_optimize(b);
    clobber_memory();
  }
}

// static void roundtrip_complex(picobench::state& s)
// {
//   logger::config::level() = logger::FAIL;
//   picobench::scope scope(s);

//   for (size_t i = 0; i < s.iterations(); ++i)
//   {
//     LOG_DEBUG << "test" << std::endl;
//   }
// }

const std::vector<int> sizes = {100'000, 200'000, 400'000};

PICOBENCH_SUITE("json");
PICOBENCH(roundtrip_simple).iterations(sizes).samples(10);
// PICOBENCH(roundtrip_complex).iterations(sizes).samples(10);
