// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#define VERBOSE_RAFT_LOGGING

#include "driver.h"

#include "ccf/ds/hash.h"

#include <cassert>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>

using namespace std;

std::unique_ptr<threading::ThreadMessaging>
  threading::ThreadMessaging::singleton = nullptr;

namespace threading
{
  std::map<std::thread::id, uint16_t> thread_ids;
}

constexpr auto shash = ds::fnv_1a<size_t>;

int main(int argc, char** argv)
{
  const regex delim{","};
  size_t lineno = 1;
  auto driver = make_shared<RaftDriver>();

  if (argc < 2)
  {
    throw std::runtime_error(
      "Too few arguments - first must be path to scenario");
  }

  // Log all raft steps to stdout (python wrapper raft_scenario_runner.py
  // filters them).
  logger::config::add_text_console_logger();
  // logger::config::add_json_console_logger();
  // cmake with ".. -DVERBOSE_LOGGING=DEBUG"
  logger::config::level() = logger::DEBUG;
  
  threading::ThreadMessaging::init(1);

  const std::string filename = argv[1];

  std::ifstream fstream;
  fstream.open(filename);

  if (!fstream.is_open())
  {
    throw std::runtime_error(
      fmt::format("File {} does not exist or could not be opened", filename));
  }

  string line;
  while (getline(fstream, line))
  {
    // Strip off any comments (preceded with #)
    const auto comment_start = line.find_first_of("#");
    if (comment_start != std::string::npos)
    {
      line.erase(comment_start);
    }
    // Strip off any trailing whitespace
    line.erase(line.find_last_not_of(" \t\n\r\f\v") + 1);
    vector<string> items{
      sregex_token_iterator(line.begin(), line.end(), delim, -1),
      std::sregex_token_iterator()};
    std::shared_ptr<std::vector<uint8_t>> data;
    const std::string& in = items[0].c_str();
    if (in.starts_with("===="))
    {
      // Terminate early if four or more '=' appear on a line.
      return 0;
    }
    switch (shash(in))
    {
      case shash("nodes"):
        assert(items.size() >= 2);
        items.erase(items.begin());
        driver->create_new_nodes(items);
        break;
      case shash("connect"):
        assert(items.size() == 3);
        driver->connect(items[1], items[2]);
        break;
      case shash("periodic_one"):
        assert(items.size() == 3);
        driver->periodic_one(items[1], ms(stoi(items[2])));
        break;
      case shash("periodic_all"):
        assert(items.size() == 2);
        driver->periodic_all(ms(stoi(items[1])));
        break;
      case shash("state_one"):
        assert(items.size() == 2);
        driver->state_one(items[1]);
        break;
      case shash("state_all"):
        assert(items.size() == 1);
        driver->state_all();
        break;
      case shash("shuffle_one"):
        assert(items.size() == 2);
        driver->shuffle_messages_one(items[1]);
        break;
      case shash("shuffle_all"):
        assert(items.size() == 1);
        driver->shuffle_messages_all();
        break;
      case shash("dispatch_one"):
        assert(items.size() == 2);
        driver->dispatch_one(items[1]);
        break;
      case shash("dispatch_all"):
        assert(items.size() == 1);
        driver->dispatch_all();
        break;
      case shash("dispatch_all_once"):
        assert(items.size() == 1);
        driver->dispatch_all_once();
        break;
      case shash("replicate"):
        assert(items.size() == 3);
        data = std::make_shared<std::vector<uint8_t>>(
          items[2].begin(), items[2].end());
        driver->replicate(items[1], data, lineno);
        break;
      case shash("disconnect"):
        assert(items.size() == 3);
        driver->disconnect(items[1], items[2]);
        break;
      case shash("disconnect_node"):
        assert(items.size() == 2);
        driver->disconnect_node(items[1]);
        break;
      case shash("reconnect"):
        assert(items.size() == 3);
        driver->reconnect(items[1], items[2]);
        break;
      case shash("reconnect_node"):
        assert(items.size() == 2);
        driver->reconnect_node(items[1]);
        break;
      case shash("drop_pending"):
        assert(items.size() == 2);
        driver->drop_pending(items[1]);
        break;
      case shash("drop_pending_to"):
        assert(items.size() == 3);
        driver->drop_pending_to(items[1], items[2]);
        break;
      case shash("assert_state_sync"):
        assert(items.size() == 1);
        driver->assert_state_sync(lineno);
        break;
      case shash("assert_is_backup"):
        assert(items.size() == 2);
        driver->assert_is_backup(items[1], lineno);
        break;
      case shash("assert_is_primary"):
        assert(items.size() == 2);
        driver->assert_is_primary(items[1], lineno);
        break;
      case shash("assert_is_candidate"):
        assert(items.size() == 2);
        driver->assert_is_candidate(items[1], lineno);
        break;
      case shash("assert_is_retiring"):
        assert(items.size() == 2);
        driver->assert_is_retiring(items[1], lineno);
        break;
      case shash("assert_is_retired"):
        assert(items.size() == 2);
        driver->assert_is_retired(items[1], lineno);
        break;
      case shash("assert_commit_idx"):
        assert(items.size() == 3);
        driver->assert_commit_idx(items[1], items[2], lineno);
        break;
      case shash("replicate_new_configuration"):
        assert(items.size() >= 3);
        items.erase(items.begin());
        driver->replicate_new_configuration(
          items[0], {std::next(items.begin()), items.end()}, lineno);
        break;
      case shash("create_new_node"):
        assert(items.size() == 2);
        driver->create_new_node(items[1]);
        break;
      case shash(""):
        // Ignore empty lines
        break;
      default:
        cerr << "Unknown action '" << items[0] << "' at line " << lineno
             << endl;
    }
    ++lineno;
  }

  return 0;
}
