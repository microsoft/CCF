// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "logger.h"
#include "ring_buffer.h"
#include "spin_lock.h"
#include "thread_messaging.h"

#include <atomic>
#include <condition_variable>
#include <map>
#include <stdexcept>

namespace messaging
{
  using Handler = std::function<void(const uint8_t*, size_t)>;

  class no_handler : public std::logic_error
  {
    using logic_error::logic_error;
  };

  class already_handled : public std::logic_error
  {
    using logic_error::logic_error;
  };

  template <typename MessageType>
  class Dispatcher
  {
    // Store a name to distinguish error messages
    char const* const name;

    std::map<MessageType, Handler> handlers;
    std::map<MessageType, char const*> message_labels;

    std::string get_error_prefix()
    {
      return std::string("[") + std::string(name) + std::string("] ");
    }

    static std::string build_message_name(
      MessageType m, char const* s = nullptr)
    {
      return std::string("<") + (s == nullptr ? "unknown" : s) + ":" +
        std::to_string(m) + ">";
    }

    std::string get_message_name(MessageType m)
    {
      const auto it = message_labels.find(m);
      if (it == message_labels.end())
      {
        return build_message_name(m);
      }

      return build_message_name(m, it->second);
    }

  public:
    Dispatcher(char const* name) : name(name), handlers() {}

    /** Set a callback for this message type
     *
     * Each message type may have a single handler registered at a time. Every
     * time a message with this type is encountered, the handler will receive a
     * callback with the raw message data.
     *
     * The handler will remain registered and continue to receive messages until
     * it is explicitly removed by a call to remove_message_handler.
     *
     * @throws already_handled if a handler is already registered for
     * this type.
     */
    void set_message_handler(
      MessageType m, char const* message_label, Handler h)
    {
      // Check for presence first, so we only copy if we're actually inserting
      auto it = handlers.find(m);
      if (it != handlers.end())
      {
        throw already_handled(
          get_error_prefix() + "MessageType " + std::to_string(m) +
          " already handled by " + get_message_name(m) +
          ", cannot set handler for " + build_message_name(m, message_label));
      }

      LOG_DEBUG_FMT("Setting handler for {} ({})", message_label, m);
      handlers.insert(it, {m, h});

      if (message_label != nullptr)
      {
        message_labels.emplace(m, message_label);
      }
    }

    /** Remove the callback for this message type
     *
     * The handler will be erased and will not receive any future messages
     * from this Dispatcher.
     *
     * @throws no_handler if no handler is registered for this type.
     */
    void remove_message_handler(MessageType m)
    {
      auto it = handlers.find(m);
      if (it == handlers.end())
      {
        throw no_handler(
          get_error_prefix() +
          "Can't remove non-existent handler for this message: " +
          get_message_name(m));
      }

      handlers.erase(it);
    }

    /** Is handler already registered for this message type
     *
     * @returns true iff there is an active handler for type, which has not
     * been removed.
     */
    bool has_handler(MessageType m)
    {
      return handlers.find(m) != handlers.end();
    }

    /** Dispatch a single message
     *
     * If there is a handler registered for this type, it will be called with
     * the given message body.
     *
     * @throws no_handler if no handler is registered for this type.
     */
    void dispatch(MessageType m, const uint8_t* data, size_t size)
    {
      auto it = handlers.find(m);
      if (it == handlers.end())
      {
        throw no_handler(
          get_error_prefix() +
          "No handler for this message: " + get_message_name(m));
      }

      // Handlers may register or remove handlers, so iterator is invalidated
      it->second(data, size);
    }
  };

  using RingbufferDispatcher = Dispatcher<ringbuffer::Message>;

  class BufferProcessor
  {
    RingbufferDispatcher dispatcher;
    std::atomic<bool> finished;

  public:
    BufferProcessor(char const* name = "") : dispatcher(name), finished(false)
    {}

    RingbufferDispatcher& get_dispatcher()
    {
      return dispatcher;
    }

    template <typename... Ts>
    void set_message_handler(Ts&&... ts)
    {
      dispatcher.set_message_handler(std::forward<Ts>(ts)...);
    }

    void set_finished(bool v = true)
    {
      finished.store(v);
    }

    size_t read_n(size_t max_messages, ringbuffer::Reader& r)
    {
      size_t total_read = 0;

      while (!finished.load() && total_read < max_messages)
      {
        // Read one at a time so we don't process any after being told to stop
        auto read = r.read(
          1,
          [& d = dispatcher](
            ringbuffer::Message m, const uint8_t* data, size_t size) {
            d.dispatch(m, data, size);
          });

        total_read += read;

        if (read == 0)
        {
          break;
        }
      }

      return total_read;
    };

    size_t run(ringbuffer::Reader& r)
    {
      size_t total_read = 0;

      uint16_t tid = thread_ids[std::this_thread::get_id()];
      enclave::Task& task =
        enclave::ThreadMessaging::thread_messaging.get_task(tid);

      while (!finished.load())
      {
        auto num_read = read_n(-1, r);
        if (num_read != 0)
        {
          total_read += num_read;
        }

        bool task_run =
          enclave::ThreadMessaging::thread_messaging.run_one(task);

        if (num_read == 0 && !task_run)
        {
          CCF_PAUSE();
        }
      }

      return total_read;
    }
  };

  // The last variadic argument is expected to be the handler itself. It is
  // variadic so that you can use an inline lambda, _with commas_. The
  // preprocessor will blindly paste this as (what it thinks are) multiple
  // arguments to set_message_handler, and the real processor will recognise
  // will read it as the original lambda.
#define DISPATCHER_SET_MESSAGE_HANDLER(DISP, MSG, ...) \
  DISP.set_message_handler(MSG, #MSG, __VA_ARGS__)
}
