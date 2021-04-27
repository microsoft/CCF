// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "enclave/interface.h"

#include <uv.h>
#include <chrono>
#include <queue>
#include <unordered_map>

namespace asynchost
{
  class ProcessLauncher
  {
    static constexpr size_t max_processes = 8;

    bool stopping = false;

    struct QueueEntry
    {
      LaunchHostProcessMessage msg;
      std::chrono::steady_clock::time_point queued_at;
    };

    std::queue<QueueEntry> queued;

    struct ProcessEntry
    {
      LaunchHostProcessMessage msg;
      std::chrono::steady_clock::time_point started_at;
    };

    std::unordered_map<pid_t, ProcessEntry> running;  

    void maybe_process_next_entry() {
      if (stopping || queued.empty() || running.size() >= max_processes) {
        return;
      }
      auto entry = std::move(queued.front());
      queued.pop();
      handle_entry(std::move(entry));
    }

    void handle_entry(QueueEntry&& entry)
    {
      auto now = std::chrono::steady_clock::now();
      auto queue_time_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
          now - entry.queued_at)
          .count();

      auto& msg = entry.msg;
      auto& args = msg.args;

      std::vector<const char*> argv;
      for (size_t i = 0; i < args.size(); i++)
      {
        argv.push_back(args.at(i).c_str());
      }
      argv.push_back(nullptr);

      auto handle = new uv_process_t;
      handle->data = this;
      
      uv_process_options_t options = {};
      options.file = argv.at(0);
      options.args = const_cast<char**>(argv.data());
      options.exit_cb = ProcessLauncher::on_process_exit;

      auto rc = uv_spawn(uv_default_loop(), handle, &options);

      if (rc != 0)
      {
        LOG_FAIL_FMT(
          "Error starting host process: {}", uv_strerror(rc));
        return;
      }

      LOG_DEBUG_FMT(
        "Launching host process: pid={} queuetime={}ms cmd={}",
        handle->pid,
        queue_time_ms,
        fmt::join(args, " "));

      auto started_at = std::chrono::steady_clock::now();
      ProcessEntry process_entry {
        std::move(entry.msg),
        started_at
      };
      running.insert({handle->pid, std::move(process_entry)});
    }

    static void on_process_exit(uv_process_t* handle, int64_t exit_status, int term_signal) {
      static_cast<ProcessLauncher*>(handle->data)->on_process_exit(handle, exit_status);
    }

    void on_process_exit(uv_process_t* handle, int64_t exit_status) {
      auto& process = running.at(handle->pid);

      auto t_end = std::chrono::steady_clock::now();
      auto runtime_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(t_end - process.started_at)
          .count();

      LOG_DEBUG_FMT(
        "Host process exited: pid={} status={} runtime={}ms cmd={}",
        handle->pid,
        exit_status,
        runtime_ms,
        fmt::join(process.msg.args, " "));

      running.erase(handle->pid);
      
      maybe_process_next_entry();

      uv_close((uv_handle_t*)handle, ProcessLauncher::on_close);
    }

    static void on_close(uv_handle_t* handle)
    {
       delete handle;
    }

  public:
    void register_message_handlers(
      messaging::Dispatcher<ringbuffer::Message>& disp)
    {
      DISPATCHER_SET_MESSAGE_HANDLER(
        disp,
        AppMessage::launch_host_process,
        [this](const uint8_t* data, size_t size) {
          auto [json] =
            ringbuffer::read_message<AppMessage::launch_host_process>(
              data, size);

          auto obj = nlohmann::json::parse(json);
          auto msg = obj.get<LaunchHostProcessMessage>();

          auto queued_at = std::chrono::steady_clock::now();
          QueueEntry entry{msg, queued_at};

          LOG_DEBUG_FMT("Queueing host process launch: {}", json);

          queued.push(std::move(entry));

          maybe_process_next_entry();
        });
    }

    void stop()
    {
      stopping = true;
    }
  };
}
