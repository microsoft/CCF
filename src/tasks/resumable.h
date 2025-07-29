// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>

namespace ccf::tasks
{
  struct IResumable;
  void resume_task(std::unique_ptr<IResumable>&& resumable);

  struct IResumable
  {
  private:
    virtual void resume() = 0;

  public:
    virtual ~IResumable() = default;

    friend void ccf::tasks::resume_task(
      std::unique_ptr<IResumable>&& resumable);
  };

  using Resumable = std::unique_ptr<IResumable>;

  Resumable pause_current_task();
  void resume_task(Resumable&& resumable);
}