// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ds/messaging.h"
#include "enclave/interface.h"

#include <chrono>
#include <queue>
#include <unordered_map>
#include <uv.h>

namespace asynchost
{
  struct ProcessPipe : public with_uv_handle<uv_pipe_t>
  {
  public:
    ProcessPipe()
    {
      uv_handle.data = this;
      uv_pipe_init(uv_default_loop(), &uv_handle, 0);
    }
    virtual ~ProcessPipe() = default;

    uv_stream_t* stream()
    {
      return (uv_stream_t*)&uv_handle;
    }

  protected:
    pid_t pid = 0;
  };

  /**
   * Read the output of a process line by line and print each one to our logs.
   */
  class ProcessReader : public ProcessPipe
  {
    static constexpr size_t max_read_size = 16384;

  public:
    ProcessReader(std::string name) : name(name) {}

    void start(pid_t pid)
    {
      this->pid = pid;

      int rc = uv_read_start((uv_stream_t*)&uv_handle, on_alloc_cb, on_read_cb);
      if (rc < 0)
      {
        LOG_FAIL_FMT("uv_read_start failed: {}", uv_strerror(rc));
        close();
      }
    }

  private:
    static void on_alloc_cb(
      uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
    {
      static_cast<ProcessReader*>(handle->data)->on_alloc(suggested_size, buf);
    }

    static void on_read_cb(
      uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf)
    {
      static_cast<ProcessReader*>(handle->data)->on_read(nread, buf);
    }

    void on_alloc(size_t suggested_size, uv_buf_t* buf)
    {
      auto alloc_size = std::min<size_t>(suggested_size, max_read_size);
      LOG_TRACE_FMT(
        "Allocating {} bytes for reading from host process pid={}",
        alloc_size,
        pid);

      buf->base = new char[alloc_size];
      buf->len = alloc_size;
    }

    void on_read(ssize_t nread, const uv_buf_t* buf)
    {
      if (nread < 0)
      {
        LOG_DEBUG_FMT(
          "ProcessReader on_read: status={} pid={} file={}",
          uv_strerror(nread),
          pid,
          name);
        // Print any trailing text which didn't have a newline
        if (!buffer.empty())
        {
          LOG_INFO_FMT("{} from process {}: {}", name, pid, buffer);
        }
        close();
      }
      else if (nread > 0)
      {
        buffer.insert(buffer.end(), buf->base, buf->base + nread);
        LOG_DEBUG_FMT(
          "Read {} bytes from host process, total={} file={}",
          nread,
          buffer.size(),
          name);
        print_lines();
      }
      on_free(buf);
    }

    void on_free(const uv_buf_t* buf)
    {
      delete[] buf->base;
    }

    /**
     * Take each line out of the buffer and print it to the logs.
     */
    void print_lines()
    {
      auto start = buffer.begin();
      while (true)
      {
        auto newline = std::find(start, buffer.end(), '\n');
        if (newline == buffer.end())
        {
          break;
        }

        size_t count = newline - start;
        std::string_view line(&*start, count);
        LOG_INFO_FMT("{} from process {}: {}", name, pid, line);

        // Move past the newline character so we can look for the next one.
        start = newline + 1;
      }
      buffer.erase(buffer.begin(), start);
    }

    std::string name;
    std::string buffer;
  };

  /**
   * Write a byte buffer to a process' standard input.
   */
  class ProcessWriter : public ProcessPipe
  {
  public:
    ProcessWriter(std::vector<uint8_t>&& data) : buffer(std::move(data))
    {
      request.data = this;
    }

    void start(pid_t pid)
    {
      this->pid = pid;

      LOG_DEBUG_FMT(
        "Writing {} bytes to host process pid={}", buffer.size(), pid);

      uv_buf_t buf = {(char*)buffer.data(), buffer.size()};
      int rc =
        uv_write(&request, (uv_stream_t*)&uv_handle, &buf, 1, on_write_done_cb);

      if (rc < 0)
      {
        LOG_FAIL_FMT("uv_write failed: {}", uv_strerror(rc));
        close();
      }
    }

  private:
    static void on_write_done_cb(uv_write_t* req, int status)
    {
      static_cast<ProcessWriter*>(req->data)->on_write_done(req, status);
    }

    void on_write_done(uv_write_t* req, int status)
    {
      LOG_DEBUG_FMT(
        "Write to host process completed: status={} pid={}", status, pid);
      close();
    }

    uv_write_t request;
    std::vector<uint8_t> buffer;
  };

  class ProcessLauncher
  {
    static constexpr size_t max_processes = 8;

    bool stopping = false;

    struct QueueEntry
    {
      std::vector<std::string> args;
      std::vector<uint8_t> input;
      std::chrono::steady_clock::time_point queued_at;
    };

    std::queue<QueueEntry> queued;

    struct ProcessEntry
    {
      std::vector<std::string> args;
      std::chrono::steady_clock::time_point started_at;
    };

    std::unordered_map<pid_t, ProcessEntry> running;

    void maybe_process_next_entry()
    {
      if (stopping || queued.empty() || running.size() >= max_processes)
      {
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

      const auto& args = entry.args;

      std::vector<const char*> argv;
      for (size_t i = 0; i < args.size(); i++)
      {
        argv.push_back(args.at(i).c_str());
      }
      argv.push_back(nullptr);

      close_ptr<ProcessReader> stdout_reader("stdout");
      close_ptr<ProcessReader> stderr_reader("stderr");
      close_ptr<ProcessWriter> stdin_writer(std::move(entry.input));

      auto handle = new uv_process_t;
      handle->data = this;

      uv_stdio_container_t stdio[3];
      stdio[0].flags = (uv_stdio_flags)(UV_CREATE_PIPE | UV_READABLE_PIPE);
      stdio[0].data.stream = stdin_writer->stream();

      stdio[1].flags = (uv_stdio_flags)(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
      stdio[1].data.stream = stdout_reader->stream();

      stdio[2].flags = (uv_stdio_flags)(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
      stdio[2].data.stream = stderr_reader->stream();

      uv_process_options_t options = {};
      options.file = argv.at(0);
      options.args = const_cast<char**>(argv.data());
      options.exit_cb = ProcessLauncher::on_process_exit;
      options.stdio = stdio;
      options.stdio_count = 3;

      auto rc = uv_spawn(uv_default_loop(), handle, &options);
      if (rc != 0)
      {
        LOG_FAIL_FMT("Error starting host process: {}", uv_strerror(rc));
        return;
      }

      LOG_INFO_FMT(
        "Launching host process: pid={} queuetime={}ms cmd={}",
        handle->pid,
        queue_time_ms,
        fmt::join(args, " "));

      stdin_writer.release()->start(handle->pid);
      stdout_reader.release()->start(handle->pid);
      stderr_reader.release()->start(handle->pid);

      auto started_at = std::chrono::steady_clock::now();
      ProcessEntry process_entry{std::move(entry.args), started_at};
      running.insert({handle->pid, std::move(process_entry)});
    }

    static void on_process_exit(
      uv_process_t* handle, int64_t exit_status, int term_signal)
    {
      static_cast<ProcessLauncher*>(handle->data)
        ->on_process_exit(handle, exit_status);
    }

    void on_process_exit(uv_process_t* handle, int64_t exit_status)
    {
      auto& process = running.at(handle->pid);

      auto t_end = std::chrono::steady_clock::now();
      auto runtime_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                          t_end - process.started_at)
                          .count();

      if (exit_status == 0)
      {
        LOG_INFO_FMT(
          "Host process exited: pid={} status={} runtime={}ms cmd={}",
          handle->pid,
          exit_status,
          runtime_ms,
          fmt::join(process.args, " "));
      }
      else
      {
        LOG_FAIL_FMT(
          "Host process exited: pid={} status={} runtime={}ms cmd={}",
          handle->pid,
          exit_status,
          runtime_ms,
          fmt::join(process.args, " "));
      }

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
          auto [json, input] =
            ringbuffer::read_message<AppMessage::launch_host_process>(
              data, size);

          auto obj = nlohmann::json::parse(json);
          auto msg = obj.get<HostProcessArguments>();

          auto queued_at = std::chrono::steady_clock::now();
          QueueEntry entry{
            std::move(msg.args),
            std::move(input),
            queued_at,
          };

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
