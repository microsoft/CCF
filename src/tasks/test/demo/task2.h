// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <functional>
#include <memory>

struct ITaskAction
{
  // Return some value indicating how much work was done.
  virtual size_t do_action() = 0;

  virtual std::string get_name() const = 0;
};

struct ITask
{
  virtual size_t do_task() = 0;

  virtual std::string get_name() const = 0;

  virtual void defer() = 0;
  virtual void restore() = 0;
};

// TODO: Non abstract? Do I just provide a single _Task_ implementation (with
// maybe-specialisations for "basic" tasks"), and move all extensibility to
// Action?
// Key-point is that we _don't_ build a complex hierarchy of Task types, because
// each needs a strict binding (1-to-1) with an Executor so that we can defer.
// Narrowing subtypes might be fine.
// No the specific problem is _nesting_ of Tasks. It's fine to have simpler Task
// types, but Tasks-containing Tasks are problematic.
struct ITask
{
  collection<ITaskAction> actions;
  IJobBoard& job_board;

  virtual std::string get_name() const = 0;

  virtual void then(std::shared_ptr<ITask> next_task) = 0;

  // TODO: Cancel?
};