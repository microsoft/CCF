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

  const std::string name;
  Fn fn;

  BasicTask(std::string_view sv, const Fn& _fn) : name(sv), fn(_fn) {}

  void do_task() override
  {
    fn();
  }

  std::string get_name() const override
  {
    return name;
  }
};

Task make_task(std::function<void()>&& func, std::string_view sv = "[Anon]")
{
  return std::make_shared<BasicTask>(sv, std::move(func));
}