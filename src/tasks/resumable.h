// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <memory>

namespace ccf::tasks
{
  struct IResumable;
  using Resumable = std::shared_ptr<IResumable>;

  void resume_task(Resumable resumable);

  struct IResumable
  {
  private:
    virtual void resume() = 0;

  public:
    virtual ~IResumable() = default;

    friend void ccf::tasks::resume_task(Resumable resumable);
  };

  Resumable pause_current_task();
}