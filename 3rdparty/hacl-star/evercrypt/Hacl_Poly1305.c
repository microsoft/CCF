/* MIT License
 *
 * Copyright (c) 2016-2020 INRIA, CMU and Microsoft Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#include "Hacl_Poly1305.h"

static void Hacl_Poly1305_32_poly1305_init(uint64_t *ctx, uint8_t *key)
{
  uint64_t *acc = ctx;
  uint64_t *pre = ctx + (uint32_t)5U;
  uint8_t *kr = key;
  acc[0U] = (uint64_t)0U;
  acc[1U] = (uint64_t)0U;
  acc[2U] = (uint64_t)0U;
  acc[3U] = (uint64_t)0U;
  acc[4U] = (uint64_t)0U;
  uint64_t u0 = load64_le(kr);
  uint64_t lo = u0;
  uint64_t u = load64_le(kr + (uint32_t)8U);
  uint64_t hi = u;
  uint64_t mask0 = (uint64_t)0x0ffffffc0fffffffU;
  uint64_t mask1 = (uint64_t)0x0ffffffc0ffffffcU;
  uint64_t lo1 = lo & mask0;
  uint64_t hi1 = hi & mask1;
  uint64_t *r = pre;
  uint64_t *r5 = pre + (uint32_t)5U;
  uint64_t *rn = pre + (uint32_t)10U;
  uint64_t *rn_5 = pre + (uint32_t)15U;
  uint64_t r_vec0 = lo1;
  uint64_t r_vec1 = hi1;
  uint64_t f00 = r_vec0 & (uint64_t)0x3ffffffU;
  uint64_t f10 = r_vec0 >> (uint32_t)26U & (uint64_t)0x3ffffffU;
  uint64_t f20 = r_vec0 >> (uint32_t)52U | (r_vec1 & (uint64_t)0x3fffU) << (uint32_t)12U;
  uint64_t f30 = r_vec1 >> (uint32_t)14U & (uint64_t)0x3ffffffU;
  uint64_t f40 = r_vec1 >> (uint32_t)40U;
  uint64_t f0 = f00;
  uint64_t f1 = f10;
  uint64_t f2 = f20;
  uint64_t f3 = f30;
  uint64_t f4 = f40;
  r[0U] = f0;
  r[1U] = f1;
  r[2U] = f2;
  r[3U] = f3;
  r[4U] = f4;
  uint64_t f200 = r[0U];
  uint64_t f21 = r[1U];
  uint64_t f22 = r[2U];
  uint64_t f23 = r[3U];
  uint64_t f24 = r[4U];
  r5[0U] = f200 * (uint64_t)5U;
  r5[1U] = f21 * (uint64_t)5U;
  r5[2U] = f22 * (uint64_t)5U;
  r5[3U] = f23 * (uint64_t)5U;
  r5[4U] = f24 * (uint64_t)5U;
  rn[0U] = r[0U];
  rn[1U] = r[1U];
  rn[2U] = r[2U];
  rn[3U] = r[3U];
  rn[4U] = r[4U];
  rn_5[0U] = r5[0U];
  rn_5[1U] = r5[1U];
  rn_5[2U] = r5[2U];
  rn_5[3U] = r5[3U];
  rn_5[4U] = r5[4U];
}

static void Hacl_Poly1305_32_poly1305_update(uint64_t *ctx, uint32_t len, uint8_t *text)
{
  uint64_t *pre = ctx + (uint32_t)5U;
  uint64_t *acc = ctx;
  uint32_t nb = len / (uint32_t)16U;
  uint32_t rem1 = len % (uint32_t)16U;
  for (uint32_t i = (uint32_t)0U; i < nb; i = i + (uint32_t)1U)
  {
    uint8_t *block = text + i * (uint32_t)16U;
    uint64_t e[5U] = { 0U };
    uint64_t u0 = load64_le(block);
    uint64_t lo = u0;
    uint64_t u = load64_le(block + (uint32_t)8U);
    uint64_t hi = u;
    uint64_t f0 = lo;
    uint64_t f1 = hi;
    uint64_t f010 = f0 & (uint64_t)0x3ffffffU;
    uint64_t f110 = f0 >> (uint32_t)26U & (uint64_t)0x3ffffffU;
    uint64_t f20 = f0 >> (uint32_t)52U | (f1 & (uint64_t)0x3fffU) << (uint32_t)12U;
    uint64_t f30 = f1 >> (uint32_t)14U & (uint64_t)0x3ffffffU;
    uint64_t f40 = f1 >> (uint32_t)40U;
    uint64_t f01 = f010;
    uint64_t f111 = f110;
    uint64_t f2 = f20;
    uint64_t f3 = f30;
    uint64_t f41 = f40;
    e[0U] = f01;
    e[1U] = f111;
    e[2U] = f2;
    e[3U] = f3;
    e[4U] = f41;
    uint64_t b = (uint64_t)0x1000000U;
    uint64_t mask = b;
    uint64_t f4 = e[4U];
    e[4U] = f4 | mask;
    uint64_t *r = pre;
    uint64_t *r5 = pre + (uint32_t)5U;
    uint64_t r0 = r[0U];
    uint64_t r1 = r[1U];
    uint64_t r2 = r[2U];
    uint64_t r3 = r[3U];
    uint64_t r4 = r[4U];
    uint64_t r51 = r5[1U];
    uint64_t r52 = r5[2U];
    uint64_t r53 = r5[3U];
    uint64_t r54 = r5[4U];
    uint64_t f10 = e[0U];
    uint64_t f11 = e[1U];
    uint64_t f12 = e[2U];
    uint64_t f13 = e[3U];
    uint64_t f14 = e[4U];
    uint64_t a0 = acc[0U];
    uint64_t a1 = acc[1U];
    uint64_t a2 = acc[2U];
    uint64_t a3 = acc[3U];
    uint64_t a4 = acc[4U];
    uint64_t a01 = a0 + f10;
    uint64_t a11 = a1 + f11;
    uint64_t a21 = a2 + f12;
    uint64_t a31 = a3 + f13;
    uint64_t a41 = a4 + f14;
    uint64_t a02 = r0 * a01;
    uint64_t a12 = r1 * a01;
    uint64_t a22 = r2 * a01;
    uint64_t a32 = r3 * a01;
    uint64_t a42 = r4 * a01;
    uint64_t a03 = a02 + r54 * a11;
    uint64_t a13 = a12 + r0 * a11;
    uint64_t a23 = a22 + r1 * a11;
    uint64_t a33 = a32 + r2 * a11;
    uint64_t a43 = a42 + r3 * a11;
    uint64_t a04 = a03 + r53 * a21;
    uint64_t a14 = a13 + r54 * a21;
    uint64_t a24 = a23 + r0 * a21;
    uint64_t a34 = a33 + r1 * a21;
    uint64_t a44 = a43 + r2 * a21;
    uint64_t a05 = a04 + r52 * a31;
    uint64_t a15 = a14 + r53 * a31;
    uint64_t a25 = a24 + r54 * a31;
    uint64_t a35 = a34 + r0 * a31;
    uint64_t a45 = a44 + r1 * a31;
    uint64_t a06 = a05 + r51 * a41;
    uint64_t a16 = a15 + r52 * a41;
    uint64_t a26 = a25 + r53 * a41;
    uint64_t a36 = a35 + r54 * a41;
    uint64_t a46 = a45 + r0 * a41;
    uint64_t t0 = a06;
    uint64_t t1 = a16;
    uint64_t t2 = a26;
    uint64_t t3 = a36;
    uint64_t t4 = a46;
    uint64_t l = t0 + (uint64_t)0U;
    uint64_t tmp0 = l & (uint64_t)0x3ffffffU;
    uint64_t c0 = l >> (uint32_t)26U;
    uint64_t l0 = t1 + c0;
    uint64_t tmp1 = l0 & (uint64_t)0x3ffffffU;
    uint64_t c1 = l0 >> (uint32_t)26U;
    uint64_t l1 = t2 + c1;
    uint64_t tmp2 = l1 & (uint64_t)0x3ffffffU;
    uint64_t c2 = l1 >> (uint32_t)26U;
    uint64_t l2 = t3 + c2;
    uint64_t tmp3 = l2 & (uint64_t)0x3ffffffU;
    uint64_t c3 = l2 >> (uint32_t)26U;
    uint64_t l3 = t4 + c3;
    uint64_t tmp4 = l3 & (uint64_t)0x3ffffffU;
    uint64_t c4 = l3 >> (uint32_t)26U;
    uint64_t l4 = tmp0 + c4 * (uint64_t)5U;
    uint64_t tmp01 = l4 & (uint64_t)0x3ffffffU;
    uint64_t c5 = l4 >> (uint32_t)26U;
    uint64_t tmp11 = tmp1 + c5;
    uint64_t o0 = tmp01;
    uint64_t o1 = tmp11;
    uint64_t o2 = tmp2;
    uint64_t o3 = tmp3;
    uint64_t o4 = tmp4;
    acc[0U] = o0;
    acc[1U] = o1;
    acc[2U] = o2;
    acc[3U] = o3;
    acc[4U] = o4;
  }
  if (rem1 > (uint32_t)0U)
  {
    uint8_t *last1 = text + nb * (uint32_t)16U;
    uint64_t e[5U] = { 0U };
    uint8_t tmp[16U] = { 0U };
    memcpy(tmp, last1, rem1 * sizeof last1[0U]);
    uint64_t u0 = load64_le(tmp);
    uint64_t lo = u0;
    uint64_t u = load64_le(tmp + (uint32_t)8U);
    uint64_t hi = u;
    uint64_t f0 = lo;
    uint64_t f1 = hi;
    uint64_t f010 = f0 & (uint64_t)0x3ffffffU;
    uint64_t f110 = f0 >> (uint32_t)26U & (uint64_t)0x3ffffffU;
    uint64_t f20 = f0 >> (uint32_t)52U | (f1 & (uint64_t)0x3fffU) << (uint32_t)12U;
    uint64_t f30 = f1 >> (uint32_t)14U & (uint64_t)0x3ffffffU;
    uint64_t f40 = f1 >> (uint32_t)40U;
    uint64_t f01 = f010;
    uint64_t f111 = f110;
    uint64_t f2 = f20;
    uint64_t f3 = f30;
    uint64_t f4 = f40;
    e[0U] = f01;
    e[1U] = f111;
    e[2U] = f2;
    e[3U] = f3;
    e[4U] = f4;
    uint64_t b = (uint64_t)1U << rem1 * (uint32_t)8U % (uint32_t)26U;
    uint64_t mask = b;
    uint64_t fi = e[rem1 * (uint32_t)8U / (uint32_t)26U];
    e[rem1 * (uint32_t)8U / (uint32_t)26U] = fi | mask;
    uint64_t *r = pre;
    uint64_t *r5 = pre + (uint32_t)5U;
    uint64_t r0 = r[0U];
    uint64_t r1 = r[1U];
    uint64_t r2 = r[2U];
    uint64_t r3 = r[3U];
    uint64_t r4 = r[4U];
    uint64_t r51 = r5[1U];
    uint64_t r52 = r5[2U];
    uint64_t r53 = r5[3U];
    uint64_t r54 = r5[4U];
    uint64_t f10 = e[0U];
    uint64_t f11 = e[1U];
    uint64_t f12 = e[2U];
    uint64_t f13 = e[3U];
    uint64_t f14 = e[4U];
    uint64_t a0 = acc[0U];
    uint64_t a1 = acc[1U];
    uint64_t a2 = acc[2U];
    uint64_t a3 = acc[3U];
    uint64_t a4 = acc[4U];
    uint64_t a01 = a0 + f10;
    uint64_t a11 = a1 + f11;
    uint64_t a21 = a2 + f12;
    uint64_t a31 = a3 + f13;
    uint64_t a41 = a4 + f14;
    uint64_t a02 = r0 * a01;
    uint64_t a12 = r1 * a01;
    uint64_t a22 = r2 * a01;
    uint64_t a32 = r3 * a01;
    uint64_t a42 = r4 * a01;
    uint64_t a03 = a02 + r54 * a11;
    uint64_t a13 = a12 + r0 * a11;
    uint64_t a23 = a22 + r1 * a11;
    uint64_t a33 = a32 + r2 * a11;
    uint64_t a43 = a42 + r3 * a11;
    uint64_t a04 = a03 + r53 * a21;
    uint64_t a14 = a13 + r54 * a21;
    uint64_t a24 = a23 + r0 * a21;
    uint64_t a34 = a33 + r1 * a21;
    uint64_t a44 = a43 + r2 * a21;
    uint64_t a05 = a04 + r52 * a31;
    uint64_t a15 = a14 + r53 * a31;
    uint64_t a25 = a24 + r54 * a31;
    uint64_t a35 = a34 + r0 * a31;
    uint64_t a45 = a44 + r1 * a31;
    uint64_t a06 = a05 + r51 * a41;
    uint64_t a16 = a15 + r52 * a41;
    uint64_t a26 = a25 + r53 * a41;
    uint64_t a36 = a35 + r54 * a41;
    uint64_t a46 = a45 + r0 * a41;
    uint64_t t0 = a06;
    uint64_t t1 = a16;
    uint64_t t2 = a26;
    uint64_t t3 = a36;
    uint64_t t4 = a46;
    uint64_t l = t0 + (uint64_t)0U;
    uint64_t tmp0 = l & (uint64_t)0x3ffffffU;
    uint64_t c0 = l >> (uint32_t)26U;
    uint64_t l0 = t1 + c0;
    uint64_t tmp1 = l0 & (uint64_t)0x3ffffffU;
    uint64_t c1 = l0 >> (uint32_t)26U;
    uint64_t l1 = t2 + c1;
    uint64_t tmp2 = l1 & (uint64_t)0x3ffffffU;
    uint64_t c2 = l1 >> (uint32_t)26U;
    uint64_t l2 = t3 + c2;
    uint64_t tmp3 = l2 & (uint64_t)0x3ffffffU;
    uint64_t c3 = l2 >> (uint32_t)26U;
    uint64_t l3 = t4 + c3;
    uint64_t tmp4 = l3 & (uint64_t)0x3ffffffU;
    uint64_t c4 = l3 >> (uint32_t)26U;
    uint64_t l4 = tmp0 + c4 * (uint64_t)5U;
    uint64_t tmp01 = l4 & (uint64_t)0x3ffffffU;
    uint64_t c5 = l4 >> (uint32_t)26U;
    uint64_t tmp11 = tmp1 + c5;
    uint64_t o0 = tmp01;
    uint64_t o1 = tmp11;
    uint64_t o2 = tmp2;
    uint64_t o3 = tmp3;
    uint64_t o4 = tmp4;
    acc[0U] = o0;
    acc[1U] = o1;
    acc[2U] = o2;
    acc[3U] = o3;
    acc[4U] = o4;
    return;
  }
}

static void Hacl_Poly1305_32_poly1305_finish(uint8_t *tag, uint8_t *key, uint64_t *ctx)
{
  uint64_t *acc = ctx;
  uint8_t *ks = key + (uint32_t)16U;
  uint64_t f0 = acc[0U];
  uint64_t f12 = acc[1U];
  uint64_t f22 = acc[2U];
  uint64_t f32 = acc[3U];
  uint64_t f40 = acc[4U];
  uint64_t l = f0 + (uint64_t)0U;
  uint64_t tmp0 = l & (uint64_t)0x3ffffffU;
  uint64_t c0 = l >> (uint32_t)26U;
  uint64_t l0 = f12 + c0;
  uint64_t tmp1 = l0 & (uint64_t)0x3ffffffU;
  uint64_t c1 = l0 >> (uint32_t)26U;
  uint64_t l1 = f22 + c1;
  uint64_t tmp2 = l1 & (uint64_t)0x3ffffffU;
  uint64_t c2 = l1 >> (uint32_t)26U;
  uint64_t l2 = f32 + c2;
  uint64_t tmp3 = l2 & (uint64_t)0x3ffffffU;
  uint64_t c3 = l2 >> (uint32_t)26U;
  uint64_t l3 = f40 + c3;
  uint64_t tmp4 = l3 & (uint64_t)0x3ffffffU;
  uint64_t c4 = l3 >> (uint32_t)26U;
  uint64_t l4 = tmp0 + c4 * (uint64_t)5U;
  uint64_t tmp0_ = l4 & (uint64_t)0x3ffffffU;
  uint64_t c5 = l4 >> (uint32_t)26U;
  uint64_t f010 = tmp0_;
  uint64_t f110 = tmp1 + c5;
  uint64_t f210 = tmp2;
  uint64_t f310 = tmp3;
  uint64_t f410 = tmp4;
  uint64_t mh = (uint64_t)0x3ffffffU;
  uint64_t ml = (uint64_t)0x3fffffbU;
  uint64_t mask = FStar_UInt64_eq_mask(f410, mh);
  uint64_t mask1 = mask & FStar_UInt64_eq_mask(f310, mh);
  uint64_t mask2 = mask1 & FStar_UInt64_eq_mask(f210, mh);
  uint64_t mask3 = mask2 & FStar_UInt64_eq_mask(f110, mh);
  uint64_t mask4 = mask3 & ~~FStar_UInt64_gte_mask(f010, ml);
  uint64_t ph = mask4 & mh;
  uint64_t pl = mask4 & ml;
  uint64_t o0 = f010 - pl;
  uint64_t o1 = f110 - ph;
  uint64_t o2 = f210 - ph;
  uint64_t o3 = f310 - ph;
  uint64_t o4 = f410 - ph;
  uint64_t f011 = o0;
  uint64_t f111 = o1;
  uint64_t f211 = o2;
  uint64_t f311 = o3;
  uint64_t f411 = o4;
  acc[0U] = f011;
  acc[1U] = f111;
  acc[2U] = f211;
  acc[3U] = f311;
  acc[4U] = f411;
  uint64_t f00 = acc[0U];
  uint64_t f1 = acc[1U];
  uint64_t f2 = acc[2U];
  uint64_t f3 = acc[3U];
  uint64_t f4 = acc[4U];
  uint64_t f01 = f00;
  uint64_t f112 = f1;
  uint64_t f212 = f2;
  uint64_t f312 = f3;
  uint64_t f41 = f4;
  uint64_t lo = (f01 | f112 << (uint32_t)26U) | f212 << (uint32_t)52U;
  uint64_t hi = (f212 >> (uint32_t)12U | f312 << (uint32_t)14U) | f41 << (uint32_t)40U;
  uint64_t f10 = lo;
  uint64_t f11 = hi;
  uint64_t u0 = load64_le(ks);
  uint64_t lo0 = u0;
  uint64_t u = load64_le(ks + (uint32_t)8U);
  uint64_t hi0 = u;
  uint64_t f20 = lo0;
  uint64_t f21 = hi0;
  uint64_t r0 = f10 + f20;
  uint64_t r1 = f11 + f21;
  uint64_t c = (r0 ^ ((r0 ^ f20) | ((r0 - f20) ^ f20))) >> (uint32_t)63U;
  uint64_t r11 = r1 + c;
  uint64_t f30 = r0;
  uint64_t f31 = r11;
  store64_le(tag, f30);
  store64_le(tag + (uint32_t)8U, f31);
}

void Hacl_Poly1305_32_poly1305_mac(uint8_t *tag, uint32_t len, uint8_t *text, uint8_t *key)
{
  uint64_t ctx[25U] = { 0U };
  Hacl_Poly1305_32_poly1305_init(ctx, key);
  Hacl_Poly1305_32_poly1305_update(ctx, len, text);
  Hacl_Poly1305_32_poly1305_finish(tag, key, ctx);
}

