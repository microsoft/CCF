// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

extern "C"
{
#include <evercrypt/EverCrypt_Hash.h>
}

class Digest
{
public:
  inline Digest()
  {
    for (int i = 0; i < 4; i++)
      d[i] = 0;
  }
  Digest(char* s, unsigned n);
  // Effects: Creates a digest for string "s" with length "n"

  inline Digest(Digest const& x)
  {
    d[0] = x.d[0];
    d[1] = x.d[1];
    d[2] = x.d[2];
    d[3] = x.d[3];
  }

  inline ~Digest() {}
  // Effects: Deallocates all storage associated with digest.

  inline void zero()
  {
    for (int i = 0; i < 4; i++)
      d[i] = 0;
  }

  inline bool is_zero() const
  {
    return d[0] == 0;
  }

  inline bool operator==(Digest const& x) const
  {
    return (d[0] == x.d[0]) & (d[1] == x.d[1]) & (d[2] == x.d[2]) &
      (d[3] == x.d[3]);
  }

  inline bool operator==(uint64_t* e) const
  {
    return (d[0] == e[0]) & (d[1] == e[1]) & (d[2] == e[2]) & (d[3] == e[3]);
  }

  inline bool operator!=(Digest const& x) const
  {
    return !(*this == x);
  }

  inline Digest& operator=(Digest const& x)
  {
    d[0] = x.d[0];
    d[1] = x.d[1];
    d[2] = x.d[2];
    d[3] = x.d[3];
    return *this;
  }

  inline size_t hash() const
  {
    return (size_t)d[0];
  }

  char* digest()
  {
    return (char*)d;
  }
  uint64_t* udigest()
  {
    return d;
  }

  constexpr static size_t digest_size()
  {
    return sizeof(d);
  }

  struct Context
  {
    Context();
    uint32_t s[8U];
    EverCrypt_Hash_state_s scrut;
  };

  // incremental digest computation
  static unsigned block_length();
  void update(Digest::Context& ctx, char* s, unsigned n);
  // Requires: n % block_length() == 0
  // Effects: adds the digest of (s,n) to context
  void update_last(Digest::Context& ctx, const char* s, unsigned n);
  // Effects: Adds the digest of (s,n) to context with zero padding at the end
  // to the next block_length boundary if n % block_length() != 0
  void finalize(Digest::Context& ctx);
  // Effects: finalizes this digest from ctx

  void print();
  // Effects: Prints digest in stdout.

private:
  uint64_t d[4];
};

struct DigestHash
{
  size_t operator()(const Digest& d) const
  {
    return d.hash();
  }
};
