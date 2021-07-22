// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#include "driver.h"

#include "ds/hash.h"

#include <cassert>
#include <iostream>
#include <regex>
#include <string>

using namespace std;

threading::ThreadMessaging threading::ThreadMessaging::thread_messaging;
std::atomic<uint16_t> threading::ThreadMessaging::thread_count = 0;

namespace threading
{
  std::map<std::thread::id, uint16_t> thread_ids;
}

constexpr auto shash = ds::fnv_1a<size_t>;

int main(int argc, char** argv)
{
  const regex delim{","};
  size_t lineno = 1;
  auto driver = shared_ptr<RaftDriver>(nullptr);

  if (argc < 2)
  {
    throw std::runtime_error(
      "Too few arguments - first must be path to scenario");
  }

  std::ifstream fstream;
  fstream.open(argv[1]);

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
    switch (shash(items[0].c_str()))
    {
      case shash("nodes"):
        assert(items.size() >= 2);
        items.erase(items.begin());
        driver = make_shared<RaftDriver>(items);
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
        driver->replicate(items[1], data);
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
      case shash("assert_state_sync"):
        assert(items.size() == 1);
        driver->assert_state_sync();
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
