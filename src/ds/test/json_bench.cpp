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

#define DECLARE_SIMPLE_STRUCT \
  struct Simple \
  { \
    size_t x; \
    int y; \
    void randomise() \
    { \
      ::randomise(x); \
      ::randomise(y); \
    } \
  };

#define DECLARE_COMPLEX_STRUCT \
  struct Complex \
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
    std::map<size_t, Bar> m; \
    void randomise() \
    { \
      ::randomise(b); \
      ::randomise(i); \
      ::randomise(s); \
      const size_t n = rand() % 20; \
      for (auto i = 0; i < n; ++i) \
      { \
        size_t nn; \
        ::randomise(nn); \
        m[nn].randomise(); \
      } \
    } \
  };

template <typename T>
static void conv(picobench::state& s)
{
  std::vector<T> entries(s.iterations());
  for (auto& e : entries)
  {
    e.randomise();
  }

  picobench::scope scope(s);
  for (size_t i = 0; i < s.iterations(); ++i)
  {
    nlohmann::json j = entries[i];
    const auto b = j.get<T>();
    do_not_optimize(b);
    clobber_memory();
  }
}

namespace manual
{
  DECLARE_SIMPLE_STRUCT

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

  DECLARE_COMPLEX_STRUCT

  void to_json(nlohmann::json& j, const Complex::Foo& f)
  {
    j["n"] = f.n;
    j["s"] = f.s;
  }

  void to_json(nlohmann::json& j, const Complex::Bar& b)
  {
    j["a"] = b.a;
    j["b"] = b.b;
    j["foos"] = b.foos;
  }

  void to_json(nlohmann::json& j, const Complex& c)
  {
    j["b"] = c.b;
    j["i"] = c.i;
    j["s"] = c.s;
    j["m"] = c.m;
  }

  void from_json(const nlohmann::json& j, Complex::Foo& f)
  {
    f.n = j["n"];
    f.s = j["s"];
  }

  void from_json(const nlohmann::json& j, Complex::Bar& b)
  {
    b.a = j["a"];
    b.b = j["b"];
    b.foos = j["foos"].get<decltype(b.foos)>();
  }

  void from_json(const nlohmann::json& j, Complex& c)
  {
    c.b = j["b"];
    c.i = j["i"];
    c.s = j["s"];
    c.m = j["m"].get<decltype(c.m)>();
  }
}

namespace macros
{
  NAMESPACE_CONTAINS_JSON_TYPES

  DECLARE_SIMPLE_STRUCT

  DECLARE_REQUIRED_JSON_FIELDS(Simple, x, y);

  DECLARE_COMPLEX_STRUCT

  DECLARE_REQUIRED_JSON_FIELDS(Complex::Foo, n, s);
  DECLARE_REQUIRED_JSON_FIELDS(Complex::Bar, a, b, foos);
  DECLARE_REQUIRED_JSON_FIELDS(Complex, b, i, s, m);
}

const std::vector<int> sizes = {2'000, 4'000};

PICOBENCH_SUITE("simple");
PICOBENCH(conv<manual::Simple>).iterations(sizes).samples(10);
PICOBENCH(conv<macros::Simple>).iterations(sizes).samples(10);

PICOBENCH_SUITE("complex");
PICOBENCH(conv<manual::Complex>).iterations(sizes).samples(10);
PICOBENCH(conv<macros::Complex>).iterations(sizes).samples(10);
