#include "util.h"

#include <iostream>
#include <merkle++.h>

void H(const Merkle::Hash& l, const Merkle::Hash& r, Merkle::Hash& o)
{
  Merkle::sha256_compress(l, r, o);
  std::cout << "h(" << l.to_string() << ", " << r.to_string()
            << ") = " << o.to_string() << std::endl;
}

void check1()
{
  Merkle::Hash h0(
    "0000000000000000000000000000000000000000000000000000000000000000");
  Merkle::Hash h3(
    "0000030000000000000000000000000000000000000000000000000000000000");
  Merkle::Hash h9(
    "0000090000000000000000000000000000000000000000000000000000000000");

  Merkle::Hash h03;
  H(h0, h3, h03);

  Merkle::Hash h039;
  H(h03, h9, h039);

  if (
    h039 !=
    Merkle::Hash(
      "8502D28E68E258445F194BE11B10A7239B03E5BDE55A23F33C43DEDA9BDBEA80"))
    std::cout << "Error: hash mismatch" << std::endl;
}

void check2()
{
  Merkle::Hash h2a(
    "00002A0000000000000000000000000000000000000000000000000000000000");
  Merkle::Hash h36(
    "0000360000000000000000000000000000000000000000000000000000000000");
  Merkle::Hash h4b(
    "00004B0000000000000000000000000000000000000000000000000000000000");
  Merkle::Hash h54(
    "0000540000000000000000000000000000000000000000000000000000000000");

  Merkle::Hash h2a36;
  H(h2a,
    h36,
    h2a36); // 93219F40254EF129C31F99F5E40004DAA0358857DCC7FA3154F276A5107BAFE5

  Merkle::Hash h2a464b;
  H(h2a36,
    h4b,
    h2a464b); // FB97D5E2CB81D21E5B6155FAE6EAD64DC9514E7E477AE8CC8C51174719BB52B2

  Merkle::Hash h4b54;
  H(h4b,
    h54,
    h4b54); // 3D26DF03794B5E2781B5ACE81CFDC7A12F0C73C65F5AF44684FE81D6EFB3FAE9
}

int main()
{
  // check1();
  check2();

  return 0;
}