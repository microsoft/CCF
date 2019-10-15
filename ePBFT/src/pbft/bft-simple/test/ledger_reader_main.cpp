// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "Digest.h"
#include "Prepared_cert.h"
#include "cstdio"
#include "ds/serialized.h"
#include "fstream"
#include "host/ledgerio.h"
#include "keypair.h"
#include "ledger.h"
#include "types.h"

#include <CLI11/CLI11.hpp>
#include <iostream>

int main(int argc, char** argv)
{
  CLI::App app{"Run Replica Test"};

  std::string ledger_path;
  app.add_option("--path", ledger_path, "path to the ledger file", false)
    ->check(CLI::ExistingFile);

  bool skip_pre_prepare = false;
  app.add_flag(
    "--skip-pre-prepare",
    skip_pre_prepare,
    "Do not display pre-prepare messages");

  bool skip_pre_prepare_large_msg = false;
  app.add_flag(
    "--skip-pre-prepare-large-msg",
    skip_pre_prepare_large_msg,
    "Do not display pre-prepare large messages");

  bool skip_prepare = false;
  app.add_flag(
    "--skip-prepare", skip_prepare, "Do not display prepare messages");

  bool skip_view_change = false;
  app.add_flag(
    "--skip-view-change", skip_view_change, "Do not display prepare messages");

  bool skip_entry_size = false;
  app.add_flag(
    "--skip-entry-size", skip_entry_size, "Do not display entry size");

  CLI11_PARSE(app, argc, argv);

  auto ledger_io = std::make_unique<asynchost::LedgerIO>(ledger_path);
  size_t entries_read = 1;
  while (true)
  {
    auto const entry = ledger_io->read_entry(entries_read);
    if (entry.empty())
    {
      std::cout << std::endl
                << std::endl
                << "Finished processing ledger" << std::endl
                << std::flush;
      break;
    }

    entries_read++;

    if (!skip_entry_size)
    {
      std::cout << "next entry size: " << entry.size() << std::endl
                << std::endl;
    }

    auto entry_data = entry.data();
    auto data_size = entry.size();

    Ledger_header_type type =
      *reinterpret_cast<Ledger_header_type*>(const_cast<uint8_t*>(entry_data));

    if (type == Ledger_header_type::Pre_prepare_ledger_header)
    {
      auto pp_header =
        serialized::overlay<Pre_prepare_ledger_header>(entry_data, data_size);

      if (!skip_pre_prepare)
      {
        std::cout << "Pre Prepare" << std::endl;
        std::cout << "sequence_num:" << pp_header.sequence_num << std::endl;
        std::cout << "message_size:" << pp_header.message_size << std::endl;
        std::cout << "num_big_requests:" << pp_header.num_big_requests
                  << std::endl
                  << std::endl;
      }

      serialized::skip(entry_data, data_size, pp_header.message_size);

      if (pp_header.num_big_requests > 0)
      {
        for (size_t i = 0; i < pp_header.num_big_requests; ++i)
        {
          auto lm_header =
            serialized::overlay<Pre_prepare_ledger_large_message_header>(
              entry_data, data_size);

          if (!skip_pre_prepare_large_msg)
          {
            std::cout << "Pre Prepare Large Message" << std::endl;
            std::cout << "message_size:" << lm_header.message_size << std::endl
                      << std::endl;
          }

          serialized::skip(entry_data, data_size, lm_header.message_size);
        }
      }
    }
    else if (type == Ledger_header_type::Prepare_ledger_header)
    {
      auto header =
        serialized::overlay<Prepare_ledger_header>(entry_data, data_size);

      if (!skip_prepare)
      {
        std::cout << "Prepare" << std::endl;
        std::cout << "sequence_num:" << header.sequence_num << std::endl;
        std::cout << "num_prepare_signatures:" << header.num_prepare_signatures
                  << std::endl
                  << std::endl;
      }

      serialized::skip(
        entry_data,
        data_size,
        header.num_prepare_signatures * sizeof(Prepared_cert::PrePrepareProof));
    }
    else if (type == Ledger_header_type::View_change_header)
    {
      auto header =
        serialized::overlay<View_change_ledger_header>(entry_data, data_size);

      if (!skip_view_change)
      {
        std::cout << "View Change" << std::endl;
        std::cout << "id:" << header.id << std::endl;
        std::cout << "sequence_num:" << header.sequence_num << std::endl;
        std::cout << "new_view:" << header.new_view << std::endl << std::endl;
      }
    }
    else if ((int)type == EOF)
    {
      std::cout << std::endl
                << std::endl
                << "Finished processing ledger" << std::endl
                << std::flush;
      return 0;
    }
    else
    {
      std::cout << std::endl
                << std::endl
                << "UNKNOWN MESSAGE TYPE:" << (int)type << std::endl
                << std::flush;
      return (int)type;
    }
  }
}