// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "global_commit_handler.h"
#include "../aft_types.h"

namespace aft
{
  struct ViewChangeInfo
  {
    ViewChangeInfo(kv::Consensus::View view_, kv::Version min_global_commit_) :
      min_global_commit(min_global_commit_),
      view(view_)
    {}

    kv::Version min_global_commit;
    kv::Consensus::View view;
  };

  class GlobalCommitHandler : public IGlobalCommitHandler
  {
  public:
    GlobalCommitHandler(IStore& store_) : store(store_)
    {
      view_change_list.emplace_back(0, 0);
    }

    void perform_global_commit(kv::Version version, kv::Consensus::View view) override
    {
      if (version == kv::NoVersion || version <= last_global_commit_version)
      {
        return;
      }

      if (last_global_commit_view < view)
      {
        last_global_commit_view  = view;
        view_change_list.emplace_back(view, last_global_commit_version + 1);
      }
      last_global_commit_version = version;
      store.compact(version);
    }

    kv::Consensus::View get_view_for_version(kv::Version version) override
    {
      auto last_vc_info = view_change_list.back();
      if (last_vc_info.min_global_commit < version)
      {
        return last_global_commit_view;
      }

      for (auto rit = view_change_list.rbegin(); rit != view_change_list.rend();
           ++rit)
      {
        ViewChangeInfo& info = *rit;
        if (info.min_global_commit <= version)
        {
          return info.view;
        }
      }
      throw std::logic_error("should never be here");
    }

  private:
    IStore& store;
    kv::Version last_global_commit_version;
    kv::Consensus::View last_global_commit_view;
    std::vector<ViewChangeInfo> view_change_list;
  };

  std::unique_ptr<IGlobalCommitHandler> create_global_commit_handler(IStore& store)
  {
    return std::make_unique<GlobalCommitHandler>(store);
  }
}