// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once
#include <atomic>
#include <stdint.h>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// The OArray (Owning Array) owns a buffer and provides a projection onto said
// buffer via a pointer and a length.
class OArray
{
public:
  OArray(std::vector<uint8_t> d_) :
    d(std::move(d_)),
    data_(d_.data()),
    size_(d_.size())
  {}

  OArray(const OArray& other) = delete;
  OArray(OArray& other) = delete;
  OArray& operator=(const OArray& rhs) = delete;
  OArray& operator=(OArray& rhs) = delete;

  OArray(OArray&& other)
  {
    data_ = other.data_;
    size_ = other.size_;
    d = std::move(other.d);
  }
  OArray& operator=(OArray&& other)
  {
    data_ = other.data_;
    size_ = other.size_;
    d = std::move(other.d);

    return *this;
  }

  const uint8_t*& data()
  {
    return data_;
  }

  size_t& size()
  {
    return size_;
  }

private:
  const uint8_t* data_;
  size_t size_;

  std::vector<uint8_t> d;
};

template <typename T>
struct Array
{
  // pointer to the buffer
  T* p;
  // number of elements
  size_t n;
  auto rawSize() const
  {
    return n * sizeof(T);
  }

  constexpr Array() : p(nullptr), n(0) {}
  constexpr Array(T* p, size_t n) : p(p), n(n) {}

  Array(const std::string& s) :
    p(reinterpret_cast<decltype(p)>(s.data())),
    n(s.size())
  {}

  using T_NON_CONST = std::remove_const_t<T>;
  Array(std::vector<T_NON_CONST>& v) : p(v.data()), n(v.size()) {}
  Array(const std::vector<T_NON_CONST>& v) : p(v.data()), n(v.size()) {}

  template <typename U, typename V = void>
  using ENABLE_CTOR = std::enable_if_t<std::is_convertible<U*, T*>::value, V>;
  template <typename U, typename = ENABLE_CTOR<U>>
  Array(const Array<U>& b) : p(b.p), n(b.n)
  {}

  bool operator==(const Array<T>& that) const
  {
    return (that.n == n) && (that.p == p);
  }

  bool operator!=(const Array<T>& that) const
  {
    return !(*this == that);
  }

  explicit operator std::vector<T_NON_CONST>() const
  {
    return {p, p + n};
  }
};

template <typename T>
using CArray = Array<const T>;
using Buffer = Array<uint8_t>;
using CBuffer = Array<const uint8_t>;
constexpr CBuffer nullb;

template <typename T>
CBuffer asCb(const T& o)
{
  return {reinterpret_cast<const uint8_t*>(&o), sizeof(T)};
}