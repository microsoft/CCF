// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#include "Digest.h"
#include "Prepared_cert.h"
#include "cstdio"
#include "fstream"
#include "keypair.h"
#include "ledger.h"
#include "types.h"

#include <CLI11/CLI11.hpp>
#include <iostream>

size_t next_entry_size(std::ifstream& file)
{
  size_t size;
  file.read((char*)&size, sizeof(size_t));
  return size;
}

Ledger_header_type read_next_type(std::ifstream& file)
{
  int type = file.peek();
  return (Ledger_header_type)type;
}

template <typename T>
T Read_type(std::ifstream& file)
{
  T header;
  file.read((char*)&header, sizeof(T));
  return header;
}

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

  std::ifstream file(
    ledger_path.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
  if (file.is_open())
  {
    file.seekg(0, std::ios::beg);

    while (true)
    {
      auto entry_size = next_entry_size(file);
      if (!skip_entry_size)
      {
        std::cout << "next entry size: " << entry_size << std::endl
                  << std::endl;
      }

      Ledger_header_type type = read_next_type(file);
      if (type == Ledger_header_type::Pre_prepare_ledger_header)
      {
        Pre_prepare_ledger_header header =
          Read_type<Pre_prepare_ledger_header>(file);

        if (!skip_pre_prepare)
        {
          std::cout << "Pre Prepare" << std::endl;
          std::cout << "sequence_num:" << header.sequence_num << std::endl;
          std::cout << "message_size:" << header.message_size << std::endl;
          std::cout << "num_big_requests:" << header.num_big_requests
                    << std::endl
                    << std::endl;
        }
        file.seekg(header.message_size, file.cur);
      }
      else if (
        type == Ledger_header_type::Pre_prepare_ledger_large_message_header)
      {
        Pre_prepare_ledger_large_message_header header =
          Read_type<Pre_prepare_ledger_large_message_header>(file);

        if (!skip_pre_prepare_large_msg)
        {
          std::cout << "Pre Prepare Large Message" << std::endl;
          std::cout << "message_size:" << header.message_size << std::endl
                    << std::endl;
        }
        file.seekg(header.message_size, file.cur);
      }
      else if (type == Ledger_header_type::Prepare_ledger_header)
      {
        Prepare_ledger_header header = Read_type<Prepare_ledger_header>(file);

        if (!skip_prepare)
        {
          std::cout << "Prepare" << std::endl;
          std::cout << "sequence_num:" << header.sequence_num << std::endl;
          std::cout << "num_prepare_signatures:"
                    << header.num_prepare_signatures << std::endl
                    << std::endl;
        }

        file.seekg(
          header.num_prepare_signatures *
            sizeof(Prepared_cert::PrePrepareProof),
          file.cur);
      }
      else if (type == Ledger_header_type::View_change_header)
      {
        View_change_ledger_header header =
          Read_type<View_change_ledger_header>(file);

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
  else
  {
    std::cout << "Unable to open file";
  }
  file.close();
}