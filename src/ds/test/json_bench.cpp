// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "ccf/ds/json.h"
#include "ccf/ds/json_schema.h"

#define PICOBENCH_IMPLEMENT_WITH_MAIN
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

void randomise(std::string& s)
{
  s.resize(rand() % 20);
  for (auto& c : s)
  {
    c = 'a' + rand() % 26;
  }
}

void randomise(size_t& n)
{
  n = rand();
}

void randomise(int& n)
{
  n = rand();
}

void randomise(bool& b)
{
  b = rand() % 2;
}

#define DECLARE_SIMPLE_STRUCT(PREFIX) \
  struct Simple_##PREFIX \
  { \
    size_t x; \
    int y; \
    void randomise() \
    { \
      ::randomise(x); \
      ::randomise(y); \
    } \
  };

#define DECLARE_COMPLEX_STRUCT(PREFIX) \
  struct Complex_##PREFIX \
  { \
    struct Foo \
    { \
      size_t n; \
      std::string s; \
      void randomise() \
      { \
        ::randomise(n); \
        ::randomise(s); \
      } \
    }; \
    struct Bar \
    { \
      size_t a; \
      size_t b; \
      std::vector<Foo> foos; \
      void randomise() \
      { \
        ::randomise(a); \
        ::randomise(b); \
        foos.resize(rand() % 20); \
        for (auto& e : foos) \
        { \
          e.randomise(); \
        } \
      } \
    }; \
    bool b; \
    int i; \
    std::string s; \
    std::vector<Bar> bars; \
    void randomise() \
    { \
      ::randomise(b); \
      ::randomise(i); \
      ::randomise(s); \
      bars.resize(rand() % 20); \
      for (auto& e : bars) \
      { \
        e.randomise(); \
      } \
    } \
  };

DECLARE_SIMPLE_STRUCT(manual)

void to_json(nlohmann::json& j, const Simple_manual& s)
{
  j["x"] = s.x;
  j["y"] = s.y;
}

void from_json(const nlohmann::json& j, Simple_manual& s)
{
  s.x = j["x"];
  s.y = j["y"];
}

DECLARE_COMPLEX_STRUCT(manual)

void to_json(nlohmann::json& j, const Complex_manual::Foo& f)
{
  j["n"] = f.n;
  j["s"] = f.s;
}

void to_json(nlohmann::json& j, const Complex_manual::Bar& b)
{
  j["a"] = b.a;
  j["b"] = b.b;
  j["foos"] = b.foos;
}

void to_json(nlohmann::json& j, const Complex_manual& c)
{
  j["b"] = c.b;
  j["i"] = c.i;
  j["s"] = c.s;
  j["bars"] = c.bars;
}

void from_json(const nlohmann::json& j, Complex_manual::Foo& f)
{
  f.n = j["n"];
  f.s = j["s"];
}

void from_json(const nlohmann::json& j, Complex_manual::Bar& b)
{
  b.a = j["a"];
  b.b = j["b"];
  b.foos = j["foos"].get<decltype(b.foos)>();
}

void from_json(const nlohmann::json& j, Complex_manual& c)
{
  c.b = j["b"];
  c.i = j["i"];
  c.s = j["s"];
  c.bars = j["bars"].get<decltype(c.bars)>();
}

DECLARE_SIMPLE_STRUCT(macros)
DECLARE_JSON_TYPE(Simple_macros);
DECLARE_JSON_REQUIRED_FIELDS(Simple_macros, x, y);

DECLARE_COMPLEX_STRUCT(macros)
DECLARE_JSON_TYPE(Complex_macros::Foo);
DECLARE_JSON_REQUIRED_FIELDS(Complex_macros::Foo, n, s);
DECLARE_JSON_TYPE(Complex_macros::Bar);
DECLARE_JSON_REQUIRED_FIELDS(Complex_macros::Bar, a, b, foos);
DECLARE_JSON_TYPE(Complex_macros);
DECLARE_JSON_REQUIRED_FIELDS(Complex_macros, b, i, s, bars);

template <typename T, typename R = T>
std::vector<R> build_entries(picobench::state& s)
{
  std::vector<R> entries(s.iterations());

  for (auto& e : entries)
  {
    T t;
    t.randomise();
    e = t;
  }

  return entries;
}

template <typename T>
static void conv(picobench::state& s)
{
  std::vector<T> entries = build_entries<T>(s);

  clobber_memory();
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    nlohmann::json j = entries[i];
    const auto b = j.get<T>();
    do_not_optimize(b);
    clobber_memory();
  }
}

template <typename T>
void valmacro(picobench::state& s)
{
  std::vector<nlohmann::json> entries = build_entries<T, nlohmann::json>(s);

  clobber_memory();
  picobench::scope scope(s);

  for (size_t i = 0; i < s.iterations(); ++i)
  {
    const auto b = entries[i].get<T>();
    do_not_optimize(b);
    clobber_memory();
  }
}

const std::vector<int> sizes = {200, 2'000};

PICOBENCH_SUITE("simple");
PICOBENCH(conv<Simple_manual>).iterations(sizes);
PICOBENCH(conv<Simple_macros>).iterations(sizes);

PICOBENCH_SUITE("complex");
PICOBENCH(conv<Complex_manual>).iterations(sizes);
PICOBENCH(conv<Complex_macros>).iterations(sizes);

PICOBENCH_SUITE("validation simple");
PICOBENCH(valmacro<Simple_macros>).iterations(sizes);

PICOBENCH_SUITE("validation complex");
PICOBENCH(valmacro<Complex_macros>).iterations(sizes);
