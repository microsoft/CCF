// Copyright (c) Microsoft Corporation.
// Copyright (c) 1999 Miguel Castro, Barbara Liskov.
// Copyright (c) 2000, 2001 Miguel Castro, Rodrigo Rodrigues, Barbara Liskov.
// Licensed under the MIT license.

#pragma once

#include "../src/consensus/consensustypes.h"
#include "Message.h"
#include "Node.h"
#include "Time.h"
#include "ds/logger.h"
#include "parameters.h"
#include "types.h"

#include <bitset>
#include <sys/time.h>

template <class T>
class Certificate
{
  //
  // A certificate is a set of "matching" messages from different
  // replicas.
  //
  // T must have the following methods:
  // bool match(T*);
  // // Effects: Returns true iff the messages match
  //
  // int id();
  // // Effects: Returns the identifier of the principal that
  // // sent the message.
  //
  // bool verify();
  // // Effects: Returns true iff the message is properly authenticated
  // // and statically correct.
  //
  // bool full();
  // // Effects: Returns true iff the message is full
  //
  // bool encode(FILE* o);
  // bool decode(FILE* i);
  // Effects: Encodes and decodes object state from stream. Return
  // true if successful and false otherwise.

public:
  Certificate(int complete = 0);
  // Requires: "complete" >= f+1 or 0
  // Effects: Creates an empty certificate. The certificate is
  // complete when it contains at least "complete" matching messages
  // from different replicas. If the complete argument is omitted (or
  // 0) it is taken to be 2f+1.

  ~Certificate();
  // Effects: Deletes certificate and all the messages it contains.

  bool add(T* m);
  // Effects: Adds "m" to the certificate and returns true provided
  // "m" satisfies:
  // 1. there is no message from "m.id()" in the certificate
  // 2. "m->verify() == true"
  // 3. if "cvalue() != 0", "cvalue()->match(m)";
  // otherwise, it has no effect on this and returns false.  This
  // becomes the owner of "m" (i.e., no other code should delete "m"
  // or retain pointers to "m".)

  bool has_message_from_replica(int id) const;

  bool add_mine(T* m);
  // Requires: The identifier of the calling principal is "m->id()"
  // and "mine()==0" and m is full.
  // Effects: If "cvalue() != 0" and "!cvalue()->match(m)", it has no
  // effect and returns false. Otherwise, adds "m" to the certificate
  // and returns. This becomes the owner of "m"

  T* mine();
  T* mine(Time& t);
  // Effects: Returns caller's message in certificate or 0 if there is
  // no such message. If "t" is supplied, sets it to point to the time
  // at which I last sent my message to all replicas.

  T* cvalue() const;
  // Effects: Returns the correct message value for this certificate
  // or 0 if this value is not known. Note that the certificate
  // retains ownership over the returned value (e.g., if clear or
  // mark_stale are called the value may be deleted.)

  T* cvalue_clear();
  // Effects: Returns the correct message value for this certificate
  // or 0 if this value is not known. If it returns the correct value,
  // it removes the message from the certificate and clears the
  // certificate (that is the caller gains ownership over the returned
  // value.)

  int num_correct() const;
  // Effects: Returns the number of messages with the correct value
  // in this.

  bool is_complete() const;
  void make_complete();
  // Effects: If cvalue() is not null, makes the certificate
  // complete.

  void mark_stale();
  // Effects: Discards all messages in certificate except mine.

  void clear();
  // Effects: Discards all messages in certificate

  bool is_empty() const;
  // Effects: Returns true iff the certificate is empty

  class Val_iter
  {
    // An iterator for yielding all the distinct values in a
    // certificate and the number of messages matching each value. The
    // certificate cannot be modified while it is being iterated on.
  public:
    Val_iter(Certificate<T>* c);
    // Effects: Return an iterator for the values in "c"

    bool get(T*& m, int& count);
    // Effects: Updates "m" to point to the next value in the
    // certificate and count to contain the number of messages
    // matching this value and returns true. If there are no more
    // values, it returns false.

  private:
    Certificate<T>* cert;
    int next;
  };
  friend class Val_iter;

  bool encode(FILE* o);
  bool decode(FILE* i);
  // Effects: Encodes and decodes object state from stream. Return
  // true if successful and false otherwise.

  void dump_state(std::ostream& os);
  // Effects: logs state for debugging

private:
  std::bitset<Max_num_replicas>
    bmap; // bitmap with replicas whose message is in this.

  class Message_val
  {
  public:
    T* m;
    int count;

    inline Message_val()
    {
      m = 0;
      count = 0;
    }
    inline void clear()
    {
      delete m;
      m = 0;
      count = 0;
    }
    inline ~Message_val()
    {
      clear();
    }
  };
  Message_val* vals; // vector with all distinct message values in this
  int max_size; // maximum number of elements in vals, f+1
  int cur_size; // current number of elements in vals

  int correct; // value is correct if it appears in at least "correct" messages
  Message_val* c; // correct certificate value or 0 if unknown.

  int complete; // certificate is complete if "num_correct() >= complete"
  int comp; // the value of complete as sent into the ctor

  T* mym; // my message in this or null if I have no message in this
  Time t_sent; // time at which mym was last sent

  ccf::NodeId f; // the value of f when starting to run

  // The implementation assumes:
  // correct > 0 and complete > correct

  void reset_f(); // If sets the f and associated values used when f has changed
                  // between the cert is created and when it is first used
};

template <class T>
inline T* Certificate<T>::mine(Time& t)
{
  if (mym)
  {
    t = t_sent;
  }
  return mym;
}

template <class T>
inline T* Certificate<T>::mine()
{
  return mym;
}

template <class T>
inline T* Certificate<T>::cvalue() const
{
  return (c) ? c->m : 0;
}

template <class T>
inline int Certificate<T>::num_correct() const
{
  return (c) ? c->count : 0;
}

template <class T>
inline bool Certificate<T>::is_complete() const
{
  return num_correct() >= complete;
}

template <class T>
inline bool Certificate<T>::has_message_from_replica(int id) const
{
  return bmap.test(id);
}

template <class T>
inline void Certificate<T>::make_complete()
{
  if (c)
  {
    c->count = complete;
  }
}

template <class T>
inline bool Certificate<T>::is_empty() const
{
  return bmap.none();
}

template <class T>
inline void Certificate<T>::clear()
{
  for (int i = 0; i < cur_size; i++)
    vals[i].clear();
  bmap.reset();
  c = 0;
  mym = 0;
  t_sent = 0;
  cur_size = 0;
}

template <class T>
inline Certificate<T>::Val_iter::Val_iter(Certificate<T>* c)
{
  cert = c;
  next = 0;
}

template <class T>
inline bool Certificate<T>::Val_iter::get(T*& m, int& count)
{
  if (next < cert->cur_size)
  {
    m = cert->vals[next].m;
    count = cert->vals[next].count;
    next++;
    return true;
  }
  return false;
}

template <class T>
Certificate<T>::Certificate(int comp_) : f(node->f()), comp(comp_)
{
  max_size = f + 1;
  vals = new Message_val[max_size];
  cur_size = 0;
  correct = f + 1;
  complete = (comp == 0) ? node->num_correct_replicas() : comp;
  c = 0;
  mym = 0;
  t_sent = 0;
}

template <class T>
Certificate<T>::~Certificate()
{
  delete[] vals;
}

template <class T>
void Certificate<T>::reset_f()
{
  f = node->f();
  max_size = f + 1;
  delete[] vals;
  vals = new Message_val[max_size];
  cur_size = 0;
  correct = f + 1;
  complete = (comp == 0) ? node->num_correct_replicas() : comp;
}

template <class T>
bool Certificate<T>::add(T* m)
{
  if (bmap.none() && f != node->f())
  {
    reset_f();
  }

  const int id = m->id();

  if (f == 0)
  {
    bmap.set(id);
    Message_val& val = vals[0];
    val.count++;
    c = vals;
    delete c->m;
    c->m = m;
    mym = m;
    c->count++;
    return true;
  }

  if (node->is_replica(id) && !bmap.test(id))
  {
    // "m" was sent by a replica that does not have a message in
    // the certificate
    if ((c == 0 || (c->count < complete && c->m->match(m))))
    {
      // add "m" to the certificate
      PBFT_ASSERT(
        id != node->id(), "verify should return false for messages from self");

      bmap.set(id);
      if (c)
      {
        c->count++;
        if (!c->m->full() && m->full())
        {
          // if c->m is not full and m is, replace c->m
          delete c->m;
          c->m = m;
        }
        else
        {
          delete m;
        }
        return true;
      }

      // Check if there is a value that matches "m"
      int i;
      for (i = 0; i < cur_size; i++)
      {
        Message_val& val = vals[i];
        if (val.m->match(m))
        {
          val.count++;
          if (val.count >= correct)
          {
            c = vals + i;
          }
          if (!val.m->full() && m->full())
          {
            // if val.m is not full and m is, replace val.m
            delete val.m;
            val.m = m;
          }
          else
          {
            delete m;
          }
          return true;
        }
      }

      // "m" has a new value.
      if (cur_size < max_size)
      {
        vals[cur_size].m = m;
        vals[cur_size++].count = 1;
        return true;
      }
      else
      {
        // Should only happen for replies to read-only requests.
        LOG_FAIL << "More than f+1 distinct values in certificate" << std::endl;
        clear();
      }
    }
    else
    {
      bmap.set(id);
    }
  }

  delete m;
  return false;
}

template <class T>
bool Certificate<T>::add_mine(T* m)
{
  PBFT_ASSERT(m->id() == node->id(), "Invalid argument");
  PBFT_ASSERT(m->full(), "Invalid argument");

  if (bmap.none() && f != node->f())
  {
    reset_f();
  }

  if (c != 0 && !c->m->match(m))
  {
    PBFT_ASSERT(
      false, "Node is faulty, more than f faulty replicas or faulty primary ");
    LOG_FATAL
      << "Node is faulty, more than f faulty replicas or faulty primary "
      << m->stag() << std::endl;
    delete m;
    return false;
  }

  if (c == 0)
  {
    // Set m to be the correct value.
    int i;
    for (i = 0; i < cur_size; i++)
    {
      if (vals[i].m->match(m))
      {
        c = vals + i;
        break;
      }
    }

    if (c == 0)
    {
      c = vals;
      vals->count = 0;
    }
  }

  if (c->m == 0)
  {
    PBFT_ASSERT(cur_size == 0, "Invalid state");
    cur_size = 1;
  }

  delete c->m;
  c->m = m;
  c->count++;
  mym = m;
  t_sent = ITimer::current_time();
  return true;
}

template <class T>
void Certificate<T>::mark_stale()
{
  if (!is_complete())
  {
    int i = 0;
    int old_cur_size = cur_size;
    if (mym)
    {
      PBFT_ASSERT(mym == c->m, "Broken invariant");
      c->m = 0;
      c->count = 0;
      c = vals;
      c->m = mym;
      c->count = 1;
      i = 1;
    }
    else
    {
      c = 0;
    }
    cur_size = i;

    for (; i < old_cur_size; i++)
      vals[i].clear();
    bmap.reset();
  }
}

template <class T>
T* Certificate<T>::cvalue_clear()
{
  if (c == 0)
  {
    return 0;
  }

  T* ret = c->m;
  c->m = 0;
  for (int i = 0; i < cur_size; i++)
  {
    if (vals[i].m == ret)
      vals[i].m = 0;
  }
  clear();

  return ret;
}

template <class T>
bool Certificate<T>::encode(FILE* o)
{
  bool ret = (fwrite((void*)&bmap, sizeof(bmap), 1, o) == sizeof(bmap));

  size_t sz = fwrite(&max_size, sizeof(int), 1, o);
  sz += fwrite(&cur_size, sizeof(int), 1, o);
  for (int i = 0; i < cur_size; i++)
  {
    int vcount = vals[i].count;
    sz += fwrite(&vcount, sizeof(int), 1, o);
    if (vcount)
    {
      ret &= vals[i].m->encode(o);
    }
  }

  sz += fwrite(&complete, sizeof(int), 1, o);

  int cindex = (c != 0) ? c - vals : -1;
  sz += fwrite(&cindex, sizeof(int), 1, o);

  bool hmym = mym != 0;
  sz += fwrite(&hmym, sizeof(bool), 1, o);

  return ret & (sz == 5U + cur_size);
}

template <class T>
bool Certificate<T>::decode(FILE* in)
{
  bool ret = (fread((void*)&bmap, sizeof(bmap), 1, in) == sizeof(bmap));

#ifndef INSIDE_ENCLAVE
  size_t sz = fread(&max_size, sizeof(int), 1, in);
  delete[] vals;

  vals = new Message_val[max_size];

  sz += fread(&cur_size, sizeof(int), 1, in);
  if (cur_size < 0 || cur_size >= max_size)
    return false;

  for (int i = 0; i < cur_size; i++)
  {
    sz += fread(&vals[i].count, sizeof(int), 1, in);
    if (vals[i].count < 0 || vals[i].count > node->num_of_replicas())
      return false;

    if (vals[i].count)
    {
      vals[i].m = (T*)new Message;
      ret &= vals[i].m->decode(in);
    }
  }

  sz += fread(&complete, sizeof(int), 1, in);
  correct = f + 1;

  int cindex;
  sz += fread(&cindex, sizeof(int), 1, in);

  bool hmym;
  sz += fread(&hmym, sizeof(bool), 1, in);

  if (cindex == -1)
  {
    c = 0;
    mym = 0;
  }
  else
  {
    if (cindex < 0 || cindex > cur_size)
      return false;
    c = vals + cindex;

    if (hmym)
      mym = c->m;
  }

  t_sent = zero_time();

  return ret & (sz == 5U + cur_size);
#else
  return true;
#endif
}

template <class T>
void Certificate<T>::dump_state(std::ostream& os)
{
  os << " bmap: " << bmap << " cur_size: " << cur_size
     << " num correct: " << num_correct() << " c: " << (void*)c
     << " is complete: " << is_complete() << " mym: " << (void*)mym
     << " tsent: " << t_sent << std::endl;
}
