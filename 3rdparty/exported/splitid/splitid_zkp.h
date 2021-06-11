// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_bignum.h"
#include "splitid_ec.h"
#include "splitid_logging.h"
#include "splitid_util.h"

#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>

namespace SplitIdentity
{
  namespace ZKP
  {
    class CR
    {
    public:
      CR() {}

      CR(const BigNum& c, const std::vector<BigNum>& r) : c(c), r(r) {}

      CR(
        const uint8_t*& buf,
        size_t& sz,
        EC::CurveID curve = EC::CurveID::SECP384R1)
      {
        c = BigNum(buf, sz);
        size_t n = deserialise_size_t(buf, sz);
        for (size_t i = 0; i < n; i++)
        {
          r.push_back(BigNum(buf, sz));
        }
      }

      BigNum c;
      std::vector<BigNum> r;

      std::vector<uint8_t> serialise() const
      {
        std::vector<uint8_t> res = c.serialise();
        auto sz = serialise_size_t(r.size());
        res.insert(res.end(), sz.begin(), sz.end());
        for (auto& ri : r)
        {
          std::vector<uint8_t> ris = ri.serialise();
          res.insert(res.end(), ris.begin(), ris.end());
        }
        return res;
      }
    };

    static void hash_extend(EVP_MD_CTX* ctx, const std::vector<uint8_t>& buf)
    {
      auto szbuf = serialise_size_t(buf.size());
      EVP_DigestUpdate(ctx, szbuf.data(), szbuf.size());
      EVP_DigestUpdate(ctx, buf.data(), buf.size());
    }

    static void hash_extend(EVP_MD_CTX* ctx, const BigNum& n)
    {
      auto buf = n.serialise();
      EVP_DigestUpdate(ctx, buf.data(), buf.size());
    }

    static BigNum challenge(
      EVP_MD_CTX* ctx1, EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      EVP_MD_CTX* ctx2;
      CHECKNULL(ctx2 = EVP_MD_CTX_new());
      CHECK1(EVP_MD_CTX_copy_ex(ctx2, ctx1));

      uint8_t x1 = 1, x2 = 2;
      EVP_DigestUpdate(ctx1, &x1, 1);
      EVP_DigestUpdate(ctx2, &x2, 1);

      std::vector<uint8_t> d1(EVP_MD_CTX_size(ctx1));
      std::vector<uint8_t> d2(EVP_MD_CTX_size(ctx2));

      EVP_DigestFinal_ex(ctx1, d1.data(), NULL);
      EVP_DigestFinal_ex(ctx2, d2.data(), NULL);

      EVP_MD_CTX_free(ctx1);
      EVP_MD_CTX_free(ctx2);

      d1.insert(d1.end(), d2.begin(), d2.end());
      BigNum r(d1);
      r = BigNum(r.mod(r, EC::curve_parameters[curve].order));
      return r;
    }

    typedef std::pair<EC::CompressedPoint, EC::CompressedPoint> PointPair;

    static PointPair commit_openk(
      const std::vector<BigNum>& x,
      size_t base_index = 2,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      auto C = EC::commit_multi(base_index, x);
      return std::make_pair(
        EC::curve_parameters[curve].G.mul(x[0]).compress(), C.compress());
    }

    static BigNum challenge_openk(
      const PointPair& cx,
      const PointPair& cz,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      hash_extend(ctx, cx.first);
      hash_extend(ctx, cx.second);
      hash_extend(ctx, cz.first);
      hash_extend(ctx, cz.second);
      return challenge(ctx);
    }

    static CR prove_openk(
      const PointPair& cx,
      const std::vector<BigNum>& x,
      size_t base_index = 2,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      const auto& go = EC::curve_parameters[curve].order;
      std::vector<BigNum> z;
      for (size_t i = 0; i < x.size(); i++)
      {
        z.push_back(BigNum::random(go));
      }

      auto cz = commit_openk(z, base_index);
      auto c = challenge_openk(cx, cz);
      std::vector<BigNum> rs;
      for (size_t i = 0; i < x.size(); i++)
      {
        auto t1 = BigNum::mod_mul(c, x[i], go);
        auto t2 = BigNum::mod_sub(z[i], t1, go);
        rs.push_back(t2);
      }
      return CR(c, rs);
    }

    static bool verify_openk(
      const PointPair& cx, const CR& zkp, size_t base_index = 2)
    {
      PointPair Cr = commit_openk(zkp.r, base_index);
      PointPair cz = std::make_pair(
        EC::Point(cx.first).mul(zkp.c).add(EC::Point(Cr.first)).compress(),
        EC::Point(cx.second).mul(zkp.c).add(EC::Point(Cr.second)).compress());
      auto x = zkp.c;
      auto y = challenge_openk(cx, cz);
      return x == y;
    }

    static EC::Point commit_zeroes(const std::vector<BigNum>& x)
    {
      assert(x.size() == 3);
      return EC::commit_multi(2, {x[0], x[1]}).add(EC::commit_multi(6, {x[2]}));
    }

    static BigNum challenge_zeroes(
      const EC::CompressedPoint& cx, const EC::CompressedPoint& cz)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      hash_extend(ctx, cx);
      hash_extend(ctx, cz);
      return challenge(ctx);
    }

    static bool verify_zeroes(const EC::CompressedPoint& cx, const CR& proof)
    {
      auto cr = commit_zeroes(proof.r);
      auto cz = (EC::Point(cx).mul(proof.c).add(cr)).compress();
      return proof.c == challenge_zeroes(cx, cz);
    }

    static CR prove_zeroes(
      const EC::CompressedPoint& cx,
      const std::vector<BigNum>& x,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      assert(x.size() == 3);

      const auto& go = EC::curve_parameters[curve].order;

      std::vector<BigNum> z;
      for (size_t i = 0; i < 3; i++)
      {
        z.push_back(BigNum::random(go));
      }

      auto cz = commit_zeroes(z).compress();
      auto c = challenge_zeroes(cx, cz);

      std::vector<BigNum> r;
      for (size_t i = 0; i < 3; i++)
      {
        // (z[i] - c * x[i]) % order, hence a = c*x - r;
        auto v = z[i].mod_sub(c.mod_mul(x[i], go), go);
        r.push_back(v);
      }

      CR proof = {c, r};

      assert(x.size() == 3);
      assert(cx == commit_zeroes(x).compress());
      assert(verify_zeroes(cx, proof));

      return proof;
    }

    static BigNum rho_456(const std::vector<EC::CompressedPoint>& commits)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      for (auto& c : commits)
      {
        hash_extend(ctx, c);
      }
      return challenge(ctx);
    }

    static BigNum challenge_456(
      const BigNum& rho, const EC::CompressedPoint& cz)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      auto rhos = rho.serialise();
      hash_extend(ctx, rhos);
      hash_extend(ctx, cz);
      return challenge(ctx);
    }

    static bool verify_456(
      const std::vector<EC::CompressedPoint>& commits, const CR& proof)
    {
      assert(commits.size() > 0);
      auto rho = rho_456(commits);
      auto c = EC::Point(commits[0]);
      for (size_t j = 1; j < commits.size(); j++)
      {
        c = c.mul(rho).add(EC::Point(commits[j]));
      }
      auto cr = EC::commit_multi(4, proof.r);
      auto cz = c.mul(proof.c).add(cr).compress();
      return proof.c == challenge_456(rho, cz);
    }

    static CR prove_456(
      const std::vector<EC::CompressedPoint>& commits,
      const std::vector<std::vector<BigNum>>& coefficients,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      assert(commits.size() > 0);
      assert(commits.size() == coefficients.size());

      const auto& go = EC::curve_parameters[curve].order;

      auto rho = rho_456(commits);

      std::vector<BigNum> z;
      for (size_t i = 0; i < 3; i++)
      {
        z.push_back(BigNum::random(go));
      }

      auto cz = EC::commit_multi(4, z).compress();
      auto c = challenge_456(rho, cz);

      std::vector<BigNum> sum;
      for (size_t i = 0; i < 3; i++)
      {
        sum.push_back(BigNum::make_zero());
        for (size_t j = 0; j < coefficients.size(); j++)
        {
          sum.back() =
            sum.back().mod_mul(rho, go).mod_add(coefficients[j][i], go);
        }
      }

      std::vector<BigNum> r;
      for (size_t i = 0; i < 3; i++)
      {
        auto v = z[i].mod_sub(c.mod_mul(sum[i], go), go);
        r.push_back(v);
      }

      CR proof = {c, r};

      bool chk = verify_456(commits, proof);
      assert(chk);

      return proof;
    }

    static std::vector<BigNum> w_of_uv(
      const std::vector<BigNum>& u,
      const std::vector<BigNum>& v,
      const std::vector<size_t>& indices,
      const BigNum& go)
    {
      // all polynomials are represented by their evaluations at i=0..degree
      assert(u.size() == v.size());

      std::vector<BigNum> eu = u, ev = v;

      for (size_t i = u.size(); i < 2 * u.size() - 1; i++)
      {
        BigNum ibn(i);

        auto eui = BigNum::lagrange_interpolate(u, indices, ibn, go);
        auto evi = BigNum::lagrange_interpolate(v, indices, ibn, go);

        eu.push_back(eui);
        ev.push_back(evi);
      }

      std::vector<BigNum> r;
      for (size_t i = 0; i < 2 * u.size() - 1; i++)
      {
        auto euv = eu[i].mod_mul(ev[i], go);
        r.push_back(euv);
      }
      return r;
    }

    static std::pair<BigNum, BigNum> challenge_tau_rho(
      const EC::CompressedPoint& cy_pv,
      const EC::CompressedPoint& cy_aux,
      const BigNum& m,
      const BigNum& r,
      const BigNum& ak,
      const BigNum& s)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

      hash_extend(ctx, cy_pv);
      hash_extend(ctx, cy_aux);
      hash_extend(ctx, m);
      hash_extend(ctx, r);
      hash_extend(ctx, ak);
      hash_extend(ctx, s);

      EVP_MD_CTX* ctx2;
      CHECKNULL(ctx2 = EVP_MD_CTX_new());
      CHECK1(EVP_MD_CTX_copy_ex(ctx2, ctx));

      auto tau = challenge(ctx);

      hash_extend(ctx2, tau);
      auto rho = challenge(ctx2);

      return {tau, rho};
    }

    static BigNum challenge_mult(
      const EC::CompressedPoint& cy_pv,
      const EC::CompressedPoint& cy_aux,
      const BigNum& m,
      const BigNum& r,
      const BigNum& ak,
      const BigNum& s,
      const EC::CompressedPoint& cz_pv,
      const EC::CompressedPoint& cz_aux,
      const BigNum& lz)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      hash_extend(ctx, cy_pv);
      hash_extend(ctx, cy_aux);
      hash_extend(ctx, m);
      hash_extend(ctx, r);
      hash_extend(ctx, ak);
      hash_extend(ctx, s);
      hash_extend(ctx, cz_pv);
      hash_extend(ctx, cz_aux);
      hash_extend(ctx, lz);
      return challenge(ctx);
    }

    static BigNum affine_mult(
      const BigNum& m,
      const BigNum& r,
      const BigNum& ak,
      const BigNum& s,
      const BigNum& t,
      const BigNum& ut,
      const BigNum& vt,
      const BigNum& rho,
      const std::vector<BigNum>& ys,
      const BigNum& go)
    {
      assert(ys.size() >= 12);

      auto x = ys[0];
      auto k = ys[2];
      auto a = ys[3];
      auto z = ys[4];
      auto y = ys[5];
      auto u0 = ys[7];
      auto v0 = ys[8];
      auto w0 = ys[9];
      auto w3 = ys[10];
      auto w4 = ys[11];

      auto q = m.mod_add(r.mod_mul(x, go), go);
      std::vector<BigNum> u = {u0, a, a};
      std::vector<BigNum> v = {v0, k, q};

      auto ak_z = ak.mod_sub(z, go);
      auto s_y = s.mod_sub(y, go);
      auto w = {w0, ak_z, s_y, w3, w4};

      std::vector<size_t> indices = {0, 1, 2};
      assert(u.size() == 3);
      assert(v.size() == 3);

      auto v0p =
        BigNum::lagrange_interpolate(u, indices, t, go).mod_sub(ut, go);
      auto v1p =
        BigNum::lagrange_interpolate(v, indices, t, go).mod_sub(vt, go);

      indices.push_back(3);
      indices.push_back(4);

      auto v2p = BigNum::lagrange_interpolate(w, indices, t, go)
                   .mod_sub(ut.mod_mul(vt, go), go);

      auto v2p_rho_v1p = v2p.mod_mul(rho, go).mod_add(v1p, go);
      auto result = v2p_rho_v1p.mod_mul(rho, go).mod_add(v0p, go);

      return result;
    }

    typedef struct
    {
      EC::CompressedPoint cy_aux;
      BigNum u_at_tau;
      BigNum v_at_tau;
      BigNum lz;
      BigNum c;
      std::vector<BigNum> responses;
    } MultProof;

    static bool verify_mult(
      const EC::CompressedPoint& cy_pv,
      const BigNum& m,
      const BigNum& r,
      const BigNum& ak,
      const BigNum& s,
      const ZKP::MultProof& proof,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      const auto& go = EC::curve_parameters[curve].order;

      auto [tau, rho] = challenge_tau_rho(cy_pv, proof.cy_aux, m, r, ak, s);

      assert(proof.responses.size() == 12);
      std::vector<BigNum> responses_less_5(
        proof.responses.begin(),
        proof.responses.begin() + proof.responses.size() - 5);

      assert(responses_less_5.size() == 7);
      auto cr_pv = EC::commit_multi(0, responses_less_5).compress();

      std::vector<BigNum> responses_last_5(
        proof.responses.begin() + proof.responses.size() - 5,
        proof.responses.end());
      assert(responses_last_5.size() == 5);

      auto cr_aux = EC::commit_multi(7, responses_last_5).compress();

      auto cz_pv =
        EC::Point(cr_pv).add(EC::Point(cy_pv).mul(proof.c)).compress();
      auto cz_aux =
        EC::Point(cr_aux).add(EC::Point(proof.cy_aux).mul(proof.c)).compress();

      std::vector<BigNum> zero_r(proof.responses.size(), BigNum::make_zero());
      auto l0 = affine_mult(
        m, r, ak, s, tau, proof.u_at_tau, proof.v_at_tau, rho, zero_r, go);

      auto lr = affine_mult(
        m,
        r,
        ak,
        s,
        tau,
        proof.u_at_tau,
        proof.v_at_tau,
        rho,
        proof.responses,
        go);

      auto lz = lr.mod_sub(l0.mod_mul(proof.c, go), go);

      // by linearity on honest responses, f(r) - f(0) = f(z) - f(0) - c*(f(y) -
      // f(0)) hence # f(z) = f(r) + c*(0 - f(0))

      // LOG_TRACE_FMT("tau={}", tau);
      // LOG_TRACE_FMT("rho={}", rho);
      // LOG_TRACE_FMT("cr_pv={}", cr_pv);
      // LOG_TRACE_FMT("cy_pv={}", cy_pv);
      // LOG_TRACE_FMT("cy_aux={}", proof.cy_aux);
      // LOG_TRACE_FMT("m={}", m);
      // LOG_TRACE_FMT("r={}", r);
      // LOG_TRACE_FMT("ak={}", ak);
      // LOG_TRACE_FMT("s={}", s);
      // LOG_TRACE_FMT("cz_pv={}", cz_pv);
      // LOG_TRACE_FMT("cz_aux={}", cz_aux);
      // LOG_TRACE_FMT("lz={}", lz);

      auto cm =
        challenge_mult(cy_pv, proof.cy_aux, m, r, ak, s, cz_pv, cz_aux, lz);

      // LOG_TRACE_FMT("{} =?= {}", proof.c, cm);

      return proof.c == cm;
    }

    static MultProof prove_mult(
      const BigNum& m,
      const BigNum& r,
      const BigNum& ak,
      const BigNum& s,
      const std::vector<BigNum>& pv, // Add proper struct, see commit.py
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      assert(pv.size() == 7);
      const auto& go = EC::curve_parameters[curve].order;

      //  Given a public commitment Cy_pv and public parameters {m, r, ak, s},
      // we prove knowlege of private variables pv = [x, x_witness, k, a, z, y,
      // w] such that Cy_pv == commit(pv)
      //       and    ak == a*k         + z  (% order)
      //       and     s == a*(m + r*x) + y  (% order)

      auto x = pv[0];
      auto x_witness = pv[1];
      auto k = pv[2];
      auto a = pv[3];
      auto z = pv[4];
      auto y = pv[5];

      auto u0 = BigNum::random(go);
      auto v0 = BigNum::random(go);

      BigNum mrx(m.mod_add(r.mod_mul(x, go), go));
      std::vector<BigNum> u = {u0, a, a};
      std::vector<BigNum> v = {v0, k, mrx};

      std::vector<size_t> indices = {0, 1, 2};

      auto w = w_of_uv(u, v, indices, go);

      auto aux = {u0, v0, w[0], w[3], w[4]};

      std::vector<BigNum> yp = pv;
      yp.insert(yp.end(), aux.begin(), aux.end());

      // the verifier will compute Cy[pv] from committed coefficients, so we
      // only need to communicate a commitment to Cy[aux].
      auto cy_pv = EC::commit_multi(0, pv).compress();
      auto cy_aux = EC::commit_multi(7, aux).compress();

      auto [tau, rho] = challenge_tau_rho(
        cy_pv, cy_aux, m, r, ak, s); // setting the aggregate linear form

      auto u_at_tau = BigNum::lagrange_interpolate(u, indices, tau, go);
      auto v_at_tau = BigNum::lagrange_interpolate(v, indices, tau, go);

      auto am = affine_mult(m, r, ak, s, tau, u_at_tau, v_at_tau, rho, yp, go);
      assert(am == BigNum::zero());

      std::vector<BigNum> zp; // Base Schnorr proof
      for (size_t i = 0; i < yp.size(); i++)
      {
        zp.push_back(BigNum::random(go));
      }

      std::vector<BigNum> zp_pv(zp.begin(), zp.begin() + pv.size());
      std::vector<BigNum> zp_y(zp.begin() + pv.size(), zp.end());

      auto cz_pv = EC::commit_multi(0, zp_pv).compress();
      auto cz_aux = EC::commit_multi(7, zp_y).compress();

      auto lz = affine_mult(m, r, ak, s, tau, u_at_tau, v_at_tau, rho, zp, go);

      // LOG_TRACE_FMT("pv=[{}]", fmt::join(pv, ", "));

      // LOG_TRACE_FMT("tau={}", tau);
      // LOG_TRACE_FMT("rho={}", rho);
      // LOG_TRACE_FMT("cy_pv={}", cy_pv);
      // LOG_TRACE_FMT("cy_aux={}", cy_aux);
      // LOG_TRACE_FMT("m={}", m);
      // LOG_TRACE_FMT("r={}", r);
      // LOG_TRACE_FMT("ak={}", ak);
      // LOG_TRACE_FMT("s={}", s);
      // LOG_TRACE_FMT("cz_pv={}", cz_pv);
      // LOG_TRACE_FMT("cz_aux={}", cz_aux);
      // LOG_TRACE_FMT("lz={}", lz);

      auto c = challenge_mult(cy_pv, cy_aux, m, r, ak, s, cz_pv, cz_aux, lz);

      std::vector<BigNum> responses;
      for (size_t i = 0; i < yp.size(); i++)
      {
        auto q = zp[i].mod_sub(c.mod_mul(yp[i], go), go);
        responses.push_back(q);
      }

      return {cy_aux, u_at_tau, v_at_tau, lz, c, responses};
    }

    static EC::Point commit_exponent(
      const BigNum& u, EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      return EC::curve_parameters[curve].G.mul(u);
    }

    static BigNum challenge_exponent(
      const EC::CompressedPoint& U,
      const EC::CompressedPoint& Cz,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      hash_extend(ctx, U);
      hash_extend(ctx, Cz);
      return challenge(ctx);
    }

    static CR prove_exponent(
      const EC::CompressedPoint& U,
      const BigNum& u,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      const auto& go = EC::curve_parameters[curve].order;
      BigNum z = BigNum::random(go);
      EC::CompressedPoint Cz = commit_exponent(z).compress();
      BigNum c = challenge_exponent(U, Cz);
      BigNum r = z.mod_sub(c.mod_mul(u, go), go);
      return {c, {r}};
    }

    static bool verify_exponent(const EC::CompressedPoint& U, const CR& proof)
    {
      if (proof.r.size() != 1)
      {
        return false;
      }

      EC::Point Gr = commit_exponent(proof.r[0]);
      EC::CompressedPoint Cz = Gr.add(EC::Point(U).mul(proof.c)).compress();
      return proof.c == challenge_exponent(U, Cz);
    }

    static std::pair<EC::Point, EC::Point> commit_dh(
      const EC::Point& V,
      const BigNum& u,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      return std::make_pair(EC::curve_parameters[curve].G.mul(u), V.mul(u));
    }

    static BigNum challenge_dh(
      const EC::Point& U,
      const EC::Point& V,
      const EC::Point& W,
      const std::pair<EC::Point, EC::Point>& Cz)
    {
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      hash_extend(ctx, U.compress());
      hash_extend(ctx, V.compress());
      hash_extend(ctx, W.compress());
      hash_extend(ctx, Cz.first.compress());
      hash_extend(ctx, Cz.second.compress());
      return challenge(ctx);
    }

    static CR prove_dh(
      const EC::Point& U,
      const EC::Point& V,
      const EC::Point& W,
      const BigNum& u,
      EC::CurveID curve = EC::CurveID::SECP384R1)
    {
      const auto& go = EC::curve_parameters[curve].order;
      BigNum z = BigNum::random(go);
      auto Cz = commit_dh(V, z);
      BigNum c = challenge_dh(U, V, W, Cz);
      BigNum r = z.mod_sub(c.mod_mul(u, go), go);
      return {c, {r}};
    }

    static bool verify_dh(
      const EC::Point& U,
      const EC::Point& V,
      const EC::Point& W,
      const CR& proof)
    {
      if (proof.r.size() != 1)
      {
        return false;
      }

      auto GrVr = commit_dh(V, proof.r[0]);
      auto Cz0 = GrVr.first.add(U.mul(proof.c));
      auto Cz1 = GrVr.second.add(W.mul(proof.c));
      return proof.c == challenge_dh(U, V, W, std::make_pair(Cz0, Cz1));
    }
  }
}
