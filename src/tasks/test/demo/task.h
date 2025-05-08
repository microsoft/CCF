// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <memory>

struct ITask
{
  virtual void do_task() = 0;

  virtual std::string get_name() const = 0;
};

using Task = std::shared_ptr<ITask>;

struct BasicTask : public ITask
{
  using Fn = std::function<void()>;

  Fn fn;
  const std::string name;

  BasicTask(const Fn& _fn, const std::string& s = "[Anon]") : name(s), fn(_fn)
  {}

  void do_task() override
  {
    fn();
  }

  std::string get_name() const override
  {
    return name;
  }
};

template <typename T, typename... Ts>
Task make_task(Ts&&... ts)
{
  return std::make_shared<T>(std::forward<Ts>(ts)...);
}

template <typename... Ts>
Task make_basic_task(Ts&&... ts)
{
  return make_task<BasicTask>(std::forward<Ts>(ts)...);
}
