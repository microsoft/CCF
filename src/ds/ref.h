// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <utility>

template <typename T>
class Ref final
{
public:
  Ref(T* t_) : t(t_)
  {
    ++t_->counter;
  }

  Ref() : t(nullptr) {}

  Ref(const Ref& r) : t(r.t)
  {
    ++r.t->counter;
  }

  Ref<T>& operator=(const Ref<T>& other)
  {
    this->~Ref<T>();
    t = other.t;
    ++t->counter;
    return *this;
  }

  Ref(Ref&& r) : t(r.t)
  {
    r.t = nullptr;
  }

  Ref<T>& operator=(Ref<T>&& other)
  {
    this->~Ref<T>();
    t = other.t;
    other.t = nullptr;
    return *this;
  }

  ~Ref()
  {
    if (t != nullptr)
    {
      --t->counter;
      if (t->counter == 0)
      {
        delete t;
      }
      t = nullptr;
    }
  }

  T* operator->() const
  {
    return t;
  }

  T* operator*() const
  {
    return t;
  }

  bool operator!() const
  {
    return !t;
  }

private:
  T* t;
};

template <typename T, typename... Args>
Ref<T> make_Ref(Args&&... args)
{
  return Ref<T>(new T(std::forward<Args>(args)...));
}