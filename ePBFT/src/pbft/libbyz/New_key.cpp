// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#include "New_key.h"

#include "Message_tags.h"
#include "Node.h"
#include "Principal.h"
#include "ds/logger.h"
#include "pbft_assert.h"

New_key::New_key() : Message(New_key_tag, Max_message_size)
{
  unsigned symm_key[Nonce_size_u];

  rep().rid = node->new_rid();
  rep().padding = 0;
  // the one that will send the message
  std::shared_ptr<Principal> sender = node->principal();
  sender->set_out_key(symm_key, rep().rid);
  rep().id = node->id();

  // Get new keys and encrypt them
  std::shared_ptr<Principal> receiver; // principal that will receive this key
  char* dst = contents() + sizeof(New_key_rep);
  int dst_len = Max_message_size - sizeof(New_key_rep);
  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    // Skip myself iff f != 0.
    if (i == node->id() && node->f() != 0)
    {
      continue;
    }

    random_nonce(symm_key);
    receiver = node->get_principal(i);
    if (receiver != 0)
    {
      receiver->set_in_key(symm_key);
      unsigned ssize = receiver->encrypt(
        (char*)symm_key, Nonce_size, dst, dst_len, node->get_keypair());
      PBFT_ASSERT(ssize != 0, "Message is too small");
      dst += ssize;
      dst_len -= ssize;
    }
    else
    {
      // we need to advance anyway, receiver will advance for num_principals
      // anyway
      int cs = cypher_size(dst, dst_len);
      dst += cs;
      dst_len -= cs;
    }
  }
  // set my size to reflect the amount of space in use
  set_size(Max_message_size - dst_len);

  // Compute signature and update size.
  int old_size = size();
  PBFT_ASSERT(dst_len >= sender->sig_size(), "Message is too small");
  set_size(size() + sender->sig_size());
  node->gen_signature(contents(), old_size, contents() + old_size);
}

bool New_key::pre_verify()
{
  return true;
}

bool New_key::verify()
{
  // If bad principal or old message discard.
  std::shared_ptr<Principal> sender =
    node->get_principal(id()); // the one who sent the message

  if (sender == nullptr)
  {
    // Received message from unknown sender
    LOG_INFO << "Request from unknown pricipal, id:" << id() << std::endl;

    std::string pubk_sig =
      "aad14ecb5d7ca8caf5ee68d2762721a3d4fdb09b1ae4a699daf74985193b7d42";
    std::string pubk_enc =
      "893d4101c5b225c2bdc8633bb322c0ef9861e0c899014536e11196808ffc0d17";

    PrincipalInfo info;
    info.id = id();
    info.port = 0;
    info.ip = "256.256.256.256"; // Invalid
    info.pubk_sig = pubk_sig;
    info.pubk_enc = pubk_enc;
    info.host_name = "host_name";
    info.is_replica = true;

    node->add_principal(info);
    return false;
  }

  if (
    (sender == 0 || sender->last_tstamp() >= rep().rid) &&
    sender->pid() != id())
  {
    if (sender && sender->last_tstamp() == rep().rid)
    {
      // this is just a retransmission for the last key that we already have
      return true;
    }

    LOG_INFO << "time wrong, "
             << (sender == nullptr ? 0 : sender->last_tstamp()) << ", "
             << rep().rid << ", id:" << id() << std::endl;
    return false;
  }
  char* dst = contents() + sizeof(New_key_rep);
  int dst_len = size() - sizeof(New_key_rep);
  unsigned symm_key[Nonce_size_u];

  for (int i = 0; i < node->num_of_replicas(); i++)
  {
    // Skip principal that sent message iff f != 0.
    if (i == id() && node->f() != 0)
    {
      continue;
    }

    int ssize = cypher_size(dst, dst_len);
    if (ssize == 0)
    {
      LOG_INFO << "new key, " << sender << ", " << sender->last_tstamp() << ", "
               << rep().rid << ", id:" << id() << std::endl;
      return false;
    }

    if (i == node->id())
    {
      // found my key
      int ksize = node->decrypt(
        sender->get_pub_key_enc().data(), dst, (char*)symm_key, Nonce_size);
      if (ksize != Nonce_size + Tag_size)
      {
        LOG_INFO << "new key, " << sender << ", " << sender->last_tstamp()
                 << ", " << rep().rid << ", id:" << id() << std::endl;
        return false;
      }
    }

    dst += ssize;
    dst_len -= ssize;
  }

  // Check signature
  int aligned = ALIGNED_SIZE(dst - contents());

  if (
    dst_len < sender->sig_size() ||
    !sender->verify_signature(contents(), aligned, contents() + aligned, true))
  {
    LOG_INFO << "verify not working " << aligned << " < " << sender->sig_size()
             << std::endl;
    return false;
  }

  sender->set_out_key(symm_key, rep().rid, true);

  LOG_DEBUG << "GOOD - new key, " << sender << ", " << sender->last_tstamp()
            << ", " << rep().rid << ", id:" << id() << std::endl;

  return true;
}

bool New_key::convert(Message* m1, New_key*& m2)
{
  if (!m1->has_tag(New_key_tag, sizeof(New_key_rep)))
  {
    return false;
  }

  m1->trim();
  m2 = (New_key*)m1;
  return true;
}
