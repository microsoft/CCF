// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// Bindings which let Lean scenarios drive CftDriver. Each cft_* function
// implements the declaration with that extern name in
// tests/cft_scenarios/CftDriver.lean. The scenarios, and main, are Lean code
// linked into this binary.

#define VERBOSE_CFT_LOGGING

#include "driver.h"

#include "tracing/fluentd_sink.h"

#include <lean/lean.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace
{
  std::unique_ptr<CftDriver> driver;
  size_t step_count = 0;

  std::string text(b_lean_obj_arg string)
  {
    return std::string(lean_string_cstr(string), lean_string_size(string) - 1);
  }

  std::vector<std::string> texts(b_lean_obj_arg list)
  {
    std::vector<std::string> items;
    // A Lean List is either a scalar (nil) or a constructor of head and tail
    for (; !lean_is_scalar(list); list = lean_ctor_get(list, 1))
    {
      items.push_back(text(lean_ctor_get(list, 0)));
    }
    return items;
  }

  void append(std::vector<std::string>& items, const std::string& item)
  {
    items.push_back(item);
  }

  void append(
    std::vector<std::string>& items, const std::vector<std::string>& more)
  {
    items.insert(items.end(), more.begin(), more.end());
  }

  void append(std::vector<std::string>& items, uint64_t item)
  {
    items.push_back(std::to_string(item));
  }

  // The trace records each step as its name and arguments, comma separated
  template <typename... Args>
  std::string command(const Args&... args)
  {
    std::vector<std::string> items;
    (append(items, args), ...);
    return fmt::format("{}", fmt::join(items, ","));
  }

  // Lean cannot unwind C++ exceptions, so return them as IO errors, which fail
  // the scenario. f returns nothing, or the Lean value which the IO action
  // returns.
  template <typename F>
  lean_obj_res io(F&& f)
  {
    try
    {
      if constexpr (std::is_void_v<std::invoke_result_t<F&>>)
      {
        f();
        return lean_io_result_mk_ok(lean_box(0));
      }
      else
      {
        return lean_io_result_mk_ok(f());
      }
    }
    catch (const std::exception& e)
    {
      return lean_io_result_mk_error(
        lean_mk_io_user_error(lean_mk_string(e.what())));
    }
  }

  // Records a step in the trace, and names it if it fails
  template <typename F>
  auto traced(const std::string& cmd, F&& f)
  {
    ++step_count;
    try
    {
      ccf::tracing::emit(aft::trace::cft_trace_tag, "cmd", cmd);
      return f();
    }
    catch (const std::exception& e)
    {
      throw std::runtime_error(
        fmt::format("Step {} ({}) failed: {}", step_count, cmd, e.what()));
    }
  }

  enum class Invariants : uint8_t
  {
    CHECK,
    // Steps which don't alter state don't need to recheck invariants
    SKIP
  };

  template <typename F>
  lean_obj_res step(
    const std::string& cmd, F&& f, Invariants invariants = Invariants::CHECK)
  {
    return io([&]() {
      traced(cmd, [&]() {
        f();
        if (invariants == Invariants::CHECK)
        {
          driver->assert_invariants();
        }
      });
    });
  }

  lean_obj_res strings(const std::vector<std::string>& items)
  {
    auto* array = lean_mk_empty_array();
    for (const auto& item : items)
    {
      array = lean_array_push(
        array, lean_mk_string_from_bytes(item.data(), item.size()));
    }
    return array;
  }
}

extern "C"
{
  // The Lean runtime keeps its GMP constants in memory which LeakSanitizer
  // does not scan, and so reports as leaked
  const char* __lsan_default_suppressions()
  {
    return "leak:libleanshared.so\n";
  }

  // cft_scenarios_runner.py fails scenarios which write to stderr
  const char* __lsan_default_options()
  {
    return "print_suppressions=0";
  }

  lean_obj_res cft_start(b_lean_obj_arg fluentd)
  {
    return io([&]() {
      // Log all CFT steps to stdout; cft_scenarios_runner.py
      // filters them.
      ccf::logger::config::add_text_console_logger();
      ccf::logger::config::level() = ccf::LoggerLevel::DEBUG;

      const auto host_and_port = texts(fluentd);
      if (!host_and_port.empty())
      {
        ccf::tracing::FluentdSink::Endpoint endpoint{
          host_and_port.at(0), host_and_port.at(1)};
        endpoint.tag_prefix_allow_list = {"ccf.cft"};
        ccf::tracing::FluentdSink::configure(endpoint);
        ccf::tracing::FluentdSink::bind_producer(0);
        if (!ccf::tracing::FluentdSink::wait_for_connection(
              std::chrono::seconds(5)))
        {
          throw std::runtime_error("Timed out waiting for Fluentd connection");
        }
      }

      driver = std::make_unique<CftDriver>();
    });
  }

  lean_obj_res cft_finish()
  {
    return io([]() {
      // Confirm path to liveness from final state
      driver->loop_until_sync();
      driver.reset();

      ccf::tracing::FluentdSink::shutdown();
      const auto dropped = ccf::tracing::FluentdSink::dropped_count();
      if (dropped != 0)
      {
        throw std::runtime_error(
          fmt::format("cft trace exporter dropped {} events", dropped));
      }
    });
  }

  lean_obj_res cft_start_node(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("start_node", id), [&]() { driver->create_start_node(id); });
  }

  lean_obj_res cft_trust_node(b_lean_obj_arg term, b_lean_obj_arg node)
  {
    const auto t = text(term);
    const auto id = text(node);
    return step(
      command("trust_node", t, id), [&]() { driver->trust_nodes(t, {id}); });
  }

  lean_obj_res cft_trust_nodes(b_lean_obj_arg term, b_lean_obj_arg nodes)
  {
    const auto t = text(term);
    const auto ids = texts(nodes);
    return step(
      command("trust_nodes", t, ids), [&]() { driver->trust_nodes(t, ids); });
  }

  lean_obj_res cft_swap_node(
    b_lean_obj_arg term, b_lean_obj_arg retire, b_lean_obj_arg trust)
  {
    const auto t = text(term);
    const auto out = text(retire);
    const auto in = text(trust);
    return step(command("swap_node", t, out, in), [&]() {
      driver->swap_nodes(t, {out}, {in});
    });
  }

  lean_obj_res cft_swap_nodes(
    b_lean_obj_arg term, b_lean_obj_arg retire, b_lean_obj_arg trust)
  {
    const auto t = text(term);
    const auto out = texts(retire);
    const auto in = texts(trust);
    std::vector<std::string> changes;
    if (!out.empty())
    {
      changes.emplace_back("out");
      append(changes, out);
    }
    if (!in.empty())
    {
      changes.emplace_back("in");
      append(changes, in);
    }
    return step(command("swap_nodes", t, changes), [&]() {
      driver->swap_nodes(t, out, in);
    });
  }

  lean_obj_res cft_cleanup_nodes(b_lean_obj_arg term, b_lean_obj_arg nodes)
  {
    const auto t = text(term);
    const auto ids = texts(nodes);
    return step(command("cleanup_nodes", t, ids), [&]() {
      driver->cleanup_nodes(t, ids);
    });
  }

  lean_obj_res cft_nominate_successor(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(command("nominate_successor", id), [&]() {
      driver->nominate_successor(id);
    });
  }

  lean_obj_res cft_nodes(b_lean_obj_arg nodes)
  {
    const auto ids = texts(nodes);
    return step(
      command("nodes", ids), [&]() { driver->create_new_nodes(ids); });
  }

  lean_obj_res cft_create_new_node(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("create_new_node", id), [&]() { driver->create_new_node(id); });
  }

  lean_obj_res cft_replicate_new_configuration(
    b_lean_obj_arg term, b_lean_obj_arg nodes)
  {
    const auto t = text(term);
    const auto ids = texts(nodes);
    return step(command("replicate_new_configuration", t, ids), [&]() {
      driver->replicate_new_configuration(t, ids);
    });
  }

  lean_obj_res cft_replicate(b_lean_obj_arg term, b_lean_obj_arg entries)
  {
    const auto t = text(term);
    const auto batch = texts(entries);
    return step(
      command("replicate", t, batch), [&]() { driver->replicate(t, batch); });
  }

  lean_obj_res cft_periodic_one(b_lean_obj_arg node, uint64_t milliseconds)
  {
    const auto id = text(node);
    return step(command("periodic_one", id, milliseconds), [&]() {
      driver->periodic_one(id, ms(milliseconds));
    });
  }

  lean_obj_res cft_periodic_all(uint64_t milliseconds)
  {
    return step(command("periodic_all", milliseconds), [&]() {
      driver->periodic_all(ms(milliseconds));
    });
  }

  lean_obj_res cft_connect(b_lean_obj_arg first, b_lean_obj_arg second)
  {
    const auto a = text(first);
    const auto b = text(second);
    return step(command("connect", a, b), [&]() { driver->connect(a, b); });
  }

  lean_obj_res cft_disconnect(b_lean_obj_arg first, b_lean_obj_arg second)
  {
    const auto a = text(first);
    const auto b = text(second);
    return step(
      command("disconnect", a, b), [&]() { driver->disconnect(a, b); });
  }

  lean_obj_res cft_disconnect_node(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("disconnect_node", id), [&]() { driver->disconnect_node(id); });
  }

  lean_obj_res cft_reconnect(b_lean_obj_arg first, b_lean_obj_arg second)
  {
    const auto a = text(first);
    const auto b = text(second);
    return step(command("reconnect", a, b), [&]() { driver->reconnect(a, b); });
  }

  lean_obj_res cft_reconnect_node(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("reconnect_node", id), [&]() { driver->reconnect_node(id); });
  }

  lean_obj_res cft_dispatch_one(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("dispatch_one", id), [&]() { driver->dispatch_one(id); });
  }

  lean_obj_res cft_dispatch_single(b_lean_obj_arg source, b_lean_obj_arg target)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return step(command("dispatch_single", src, dst), [&]() {
      driver->dispatch_single(src, dst);
    });
  }

  lean_obj_res cft_dispatch_nth(
    b_lean_obj_arg source, b_lean_obj_arg target, uint64_t position)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return step(command("dispatch_nth", src, dst, position), [&]() {
      driver->dispatch_nth(src, dst, position);
    });
  }

  lean_obj_res cft_pending_messages(
    b_lean_obj_arg source, b_lean_obj_arg target)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return io([&]() {
      return traced(command("pending_messages", src, dst), [&]() {
        return strings(driver->pending_messages(src, dst));
      });
    });
  }

  lean_obj_res cft_dispatch_all_once()
  {
    return step(
      command("dispatch_all_once"), []() { driver->dispatch_all_once(); });
  }

  lean_obj_res cft_dispatch_all()
  {
    return step(command("dispatch_all"), []() { driver->dispatch_all(); });
  }

  lean_obj_res cft_drop_pending(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("drop_pending", id), [&]() { driver->drop_pending(id); });
  }

  lean_obj_res cft_drop_pending_to(b_lean_obj_arg source, b_lean_obj_arg target)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return step(command("drop_pending_to", src, dst), [&]() {
      driver->drop_pending_to(src, dst);
    });
  }

  lean_obj_res cft_drop_nth(
    b_lean_obj_arg source, b_lean_obj_arg target, uint64_t position)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return step(command("drop_nth", src, dst, position), [&]() {
      driver->drop_nth(src, dst, position);
    });
  }

  lean_obj_res cft_shuffle_one(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("shuffle_one", id), [&]() { driver->shuffle_messages_one(id); });
  }

  lean_obj_res cft_shuffle_all()
  {
    return step(
      command("shuffle_all"), []() { driver->shuffle_messages_all(); });
  }

  lean_obj_res cft_state_one(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("state_one", id),
      [&]() { driver->state_one(id); },
      Invariants::SKIP);
  }

  lean_obj_res cft_state_all()
  {
    return step(
      command("state_all"), []() { driver->state_all(); }, Invariants::SKIP);
  }

  lean_obj_res cft_summarise_log(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(
      command("summarise_log", id),
      [&]() { driver->summarise_log(id); },
      Invariants::SKIP);
  }

  lean_obj_res cft_summarise_logs_all()
  {
    return step(
      command("summarise_logs_all"),
      []() { driver->summarise_logs_all(); },
      Invariants::SKIP);
  }

  lean_obj_res cft_summarise_messages(
    b_lean_obj_arg source, b_lean_obj_arg target)
  {
    const auto src = text(source);
    const auto dst = text(target);
    return step(command("summarise_messages", src, dst), [&]() {
      driver->summarise_messages(src, dst);
    });
  }

  lean_obj_res cft_assert_state_sync()
  {
    return step(
      command("assert_state_sync"),
      []() { driver->assert_state_sync(); },
      Invariants::SKIP);
  }

  lean_obj_res cft_assert_commit_safety(b_lean_obj_arg node)
  {
    const auto id = text(node);
    return step(command("assert_commit_safety", id), [&]() {
      driver->assert_commit_safety(id);
    });
  }

  lean_obj_res cft_assert_commit_idx(b_lean_obj_arg node, uint64_t idx)
  {
    const auto id = text(node);
    return step(
      command("assert_commit_idx", id, idx),
      [&]() { driver->assert_commit_idx(id, std::to_string(idx)); },
      Invariants::SKIP);
  }

  lean_obj_res cft_assert_detail(
    b_lean_obj_arg node, b_lean_obj_arg detail, b_lean_obj_arg expected)
  {
    const auto id = text(node);
    const auto key = text(detail);
    const auto value = text(expected);
    return step(command("assert_detail", id, key, value), [&]() {
      driver->assert_detail(id, key, value, true);
    });
  }

  lean_obj_res cft_assert_not_detail(
    b_lean_obj_arg node, b_lean_obj_arg detail, b_lean_obj_arg unexpected)
  {
    const auto id = text(node);
    const auto key = text(detail);
    const auto value = text(unexpected);
    return step(command("assert_!detail", id, key, value), [&]() {
      driver->assert_detail(id, key, value, false);
    });
  }

  lean_obj_res cft_assert_config(
    b_lean_obj_arg node, uint64_t idx, b_lean_obj_arg nodes)
  {
    const auto id = text(node);
    const auto ids = texts(nodes);
    return step(command("assert_config", id, idx, ids), [&]() {
      driver->assert_config(id, std::to_string(idx), ids);
    });
  }

  lean_obj_res cft_assert_absent_config(b_lean_obj_arg node, uint64_t idx)
  {
    const auto id = text(node);
    return step(command("assert_absent_config", id, idx), [&]() {
      driver->assert_absent_config(id, std::to_string(idx));
    });
  }

  lean_obj_res cft_assert_last_txid(b_lean_obj_arg node, b_lean_obj_arg txid)
  {
    const auto id = text(node);
    const auto expected = text(txid);
    return step(
      command("assert_last_txid", id, expected),
      [&]() { driver->assert_last_txid(id, expected); },
      Invariants::SKIP);
  }

  lean_obj_res cft_loop_until_sync()
  {
    return step(
      command("loop_until_sync"), []() { driver->loop_until_sync(); });
  }
}
