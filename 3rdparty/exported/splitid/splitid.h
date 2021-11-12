// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "splitid_bignum.h"
#include "splitid_ec.h"
#include "splitid_formatters.h"
#include "splitid_keypair.h"
#include "splitid_logging.h"
#include "splitid_poly.h"
#include "splitid_util.h"
#include "splitid_zkp.h"

#include <map>
#include <memory>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <stdexcept>
#include <string>
#include <vector>

namespace SplitIdentity
{
  static EC::CompressedPoint compress_x_wx(
    BigNum x, BigNum wx, EC::CurveID curve = EC::CurveID::SECP384R1)
  {
    return compressed_commit_multi(0, {x, wx}, curve);
  }

  static EC::CompressedPoint compute_c_at_j(
    const std::vector<EC::CompressedPoint>& commits, size_t j)
  {
    EC::Point C;
    for (size_t i = commits.size() - 1; i != SIZE_MAX; i--)
    {
      C = C.mul(j).add(EC::Point(commits[i]));
    }
    return C.compress();
  }

  static EC::CompressedPoint lagrange_in_exp_feldman(
    const std::vector<EC::CompressedPoint>& values,
    const std::vector<size_t>& indices,
    const BigNum& j,
    EC::CurveID curve = EC::CurveID::SECP384R1)
  {
    assert(values.size() == indices.size());
    const auto& go = EC::curve_parameters[curve].order;

    EC::Point result;
    for (size_t i = 0; i < values.size(); i++)
    {
      auto lc = BigNum::lagrange_coefficient(indices, i, j, go);
      result = result.add(EC::Point(values[i]).mul(lc));
    }
    return result.compress();
  }

  static std::vector<uint8_t> hash(const std::vector<uint8_t>& msg)
  {
    unsigned int sz = 0;
    auto md = EVP_sha256();
    std::vector<uint8_t> r(EVP_MD_size(md));
    EVP_Digest(msg.data(), msg.size(), r.data(), &sz, md, NULL);
    return r;
  }

  static std::vector<std::vector<BigNum>> sum_share_polys(
    const std::vector<SharePolynomials>& deals, const BigNum& m)
  {
    assert(deals.size() > 0);
    std::vector<std::vector<BigNum>> r;

    for (size_t p = 0; p < 2; p++)
    {
      std::vector<BigNum> jt;

      const auto& poly0 = p == 0 ? deals[0].q : deals[0].q_witness;
      for (size_t u = 0; u < poly0.coefficients.size(); u++)
      {
        auto sum = BigNum::make_zero();
        for (size_t k = 0; k < deals.size(); k++)
        {
          const auto& poly_k = p == 0 ? deals[k].q : deals[k].q_witness;
          auto& c = poly_k.coefficients[u];
          sum = BigNum::mod_add(sum, c, m);
        }
        jt.push_back(sum);
      }
      r.push_back(jt);
    }

    return r;
  }

  static EC::CompressedPoint get_public_point(EVP_PKEY* key)
  {
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(key);
    EC::Point public_pnt(EC_KEY_get0_public_key(eckey));
    EC_KEY_free(eckey);
    return public_pnt.compress();
  }

  static EC::CompressedPoint get_public_point_from_pem(
    const std::vector<uint8_t>& pem)
  {
    EVP_PKEY* onid_public;
    Wrapped_BIO bio(pem.data(), pem.size());
    CHECKNULL(onid_public = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL));
    auto public_pnt = get_public_point(onid_public);
    EVP_PKEY_free(onid_public);
    return public_pnt;
  }

  static EC::CompressedPoint get_public_point(const KeyPair& kp)
  {
    return get_public_point(kp.private_key);
  }

  static std::pair<BigNum, EC::CompressedPoint> get_bignum_and_point(
    const KeyPair& kp)
  {
    EC_KEY* eckey = EVP_PKEY_get1_EC_KEY(kp.private_key);
    BigNum private_bn(EC_KEY_get0_private_key(eckey));
    EC::Point public_pnt(EC_KEY_get0_public_key(eckey));
    EC_KEY_free(eckey);
    return std::make_pair(private_bn, public_pnt.compress());
  }

  class Deal
  {
  public:
    Deal(bool defensive = false, EC::CurveID curve = EC::CurveID::SECP384R1) :
      defensive(defensive),
      curve(curve)
    {}

    virtual ~Deal() {}

    virtual std::vector<uint8_t> serialise() const
    {
      std::vector<uint8_t> r = serialise_shares();
      std::vector<uint8_t> rc = serialise_commitments();
      r.insert(r.end(), rc.begin(), rc.end());
      return r;
    }

    virtual std::vector<uint8_t> serialise_shares() const = 0;
    virtual std::vector<uint8_t> serialise_commitments() const = 0;

    virtual std::string to_string() const = 0;

  protected:
    bool defensive;
    EC::CurveID curve;
  };

  class SigningDeal : public Deal
  {
  public:
    SigningDeal(
      size_t lower_degree,
      size_t upper_degree,
      const std::vector<size_t>& indices,
      bool defensive = false,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      Deal(defensive, curve),
      lower_degree(lower_degree),
      upper_degree(upper_degree),
      defensive(defensive),
      indices_(indices)
    {
      if (lower_degree == 0)
      {
        throw std::runtime_error("need t > 0");
      }

      sample();
      compute_shares();

      if (defensive)
      {
        compute_commits();
        compute_proof();
      }
    }

    SigningDeal(const uint8_t*& buf, size_t& sz)
    {
      size_t n = deserialise_size_t(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        std::vector<BigNum> t;
        size_t m = deserialise_size_t(buf, sz);
        for (size_t j = 0; j < m; j++)
        {
          t.push_back(BigNum(buf, sz));
        }
        shares_.push_back(t);
      }

      if (sz > 0)
      {
        n = deserialise_size_t(buf, sz);
        for (size_t i = 0; i < n; i++)
        {
          size_t vs = deserialise_size_t(buf, sz);
          auto cs = EC::CompressedPoint(buf, buf + vs);
          assert(cs.size() == vs);
          buf += vs;
          sz -= vs;
          commitments_.push_back(cs);
        }
      }
    }

    virtual ~SigningDeal() {}

    const std::shared_ptr<Polynomial>& k() const
    {
      return sharings[0];
    }

    const std::shared_ptr<Polynomial>& a() const
    {
      return sharings[1];
    }

    const std::shared_ptr<Polynomial>& z() const
    {
      return sharings[2];
    }

    const std::shared_ptr<Polynomial>& y() const
    {
      return sharings[3];
    }

    const std::shared_ptr<Polynomial>& w() const
    {
      return sharings[4];
    }

    const std::vector<std::vector<BigNum>>& shares() const
    {
      return shares_;
    }

    const std::vector<EC::CompressedPoint>& commitments() const
    {
      // n compressed points
      return commitments_;
    }

    std::vector<ZKP::CR> proof()
    {
      return proof_;
    }

    virtual std::string to_string() const override
    {
      return fmt::format(
        "  shares=[{}]\n  commitments=[{}]",
        fmt::join(shares_, ", "),
        fmt::join(commitments_, ", "));
    }

    virtual std::vector<uint8_t> serialise_shares() const override
    {
      std::vector<uint8_t> r = serialise_size_t(shares_.size());
      for (auto& s : shares_)
      {
        std::vector<uint8_t> b = serialise_size_t(s.size());
        for (auto& si : s)
        {
          auto bi = si.serialise();
          b.insert(b.end(), bi.begin(), bi.end());
        }
        r.insert(r.end(), b.begin(), b.end());
      }
      return r;
    }

    virtual std::vector<uint8_t> serialise_commitments() const override
    {
      std::vector<uint8_t> r;
      std::vector<uint8_t> rc = serialise_size_t(commitments_.size());
      for (auto& c : commitments_)
      {
        std::vector<uint8_t> rcsz = serialise_size_t(c.size());
        rc.insert(rc.end(), rcsz.begin(), rcsz.end());
        rc.insert(rc.end(), c.begin(), c.end());
      }
      r.insert(r.end(), rc.begin(), rc.end());

      std::vector<uint8_t> rps = serialise_size_t(proof_.size());
      for (auto& p : proof_)
      {
        std::vector<uint8_t> rpi = p.serialise();
        rps.insert(rps.end(), rpi.begin(), rpi.end());
      }
      r.insert(r.end(), rps.begin(), rps.end());
      return r;
    }

  protected:
    size_t lower_degree, upper_degree;
    bool defensive;
    std::vector<size_t> indices_;
    std::vector<std::vector<BigNum>> shares_;
    std::vector<EC::CompressedPoint> commitments_;
    std::vector<ZKP::CR> proof_;
    std::vector<std::shared_ptr<Polynomial>> sharings;

    void sample()
    {
      sharings.push_back(
        Polynomial::sample_rss(lower_degree, lower_degree, curve));
      sharings.push_back(
        Polynomial::sample_rss(lower_degree, lower_degree, curve));
      sharings.push_back(
        Polynomial::sample_zss(2 * lower_degree, nullptr, curve));
      sharings.push_back(
        Polynomial::sample_zss(2 * lower_degree, nullptr, curve));
      if (defensive)
      {
        sharings.push_back(Polynomial::sample_rss(2 * lower_degree, 0, curve));
      }
    }

    void compute_shares()
    {
      shares_.clear();
      for (auto index : indices_)
      {
        BigNum input(index);
        std::vector<BigNum> tmp;
        for (auto s : sharings)
        {
          tmp.push_back(Polynomial::eval(
            s->coefficients, input, EC::curve_parameters[curve].order));
        }
        shares_.push_back(tmp);
      }
    }

    void compute_commits()
    {
      commitments_.clear();
      for (size_t i = 0; i < upper_degree; i++)
      {
        std::vector<BigNum> sc_i;
        for (auto& s : sharings)
        {
          assert(upper_degree <= s->coefficients.size());
          sc_i.push_back(s->coefficients[i]);
        }
        commitments_.push_back({EC::commit_multi(2, sc_i).compress()});
      }
    }

    std::vector<BigNum> coefficients(size_t i)
    {
      std::vector<BigNum> r;
      for (auto& s : sharings)
      {
        r.push_back(s->coefficients[i]);
      }
      return r;
    }

    std::vector<std::vector<BigNum>> higher_coefficients(
      size_t lower, size_t upper)
    {
      assert(sharings.size() >= 5);
      std::vector<std::vector<BigNum>> r;
      for (size_t i = lower + 1; i < upper; i++)
      {
        r.push_back(
          {z()->coefficients[i], y()->coefficients[i], w()->coefficients[i]});
      }
      return r;
    }

    void compute_proof()
    {
      assert(commitments_.size() >= upper_degree);

      auto c0 = coefficients(0);
      std::vector<BigNum> non_zero_shares = {c0[0], c0[1], c0[4]};
      proof_.clear();
      proof_.push_back(ZKP::prove_zeroes(commitments_[0], non_zero_shares));

      std::vector<EC::CompressedPoint> higher_commits;
      for (size_t i = lower_degree + 1; i < upper_degree; i++)
      {
        higher_commits.push_back(commitments_[i]);
      }
      proof_.push_back(ZKP::prove_456(
        higher_commits, higher_coefficients(lower_degree, upper_degree)));
    }
  };

  class ResharingDeal : public Deal
  {
  public:
    ResharingDeal(
      size_t t,
      size_t t_next,
      const std::vector<size_t>& indices,
      const std::vector<size_t>& next_indices,
      EC::CurveID curve = EC::CurveID::SECP384R1,
      bool init = true) :
      Deal(false, curve),
      t(t),
      t_next(t_next)
    {
      LOG_DEBUG_FMT(
        "SPLITID: resharing deal indices: {} next_indices: {} init: {} t: {} "
        "t_next: {}",
        fmt::join(indices, ", "),
        fmt::join(next_indices, ", "),
        init,
        t,
        t_next);
      if (init)
      {
        sample();
        compute_share_polynomials(indices);
        compute_commits();
      }
    }

    ResharingDeal(
      const uint8_t*& buf,
      size_t& sz,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      Deal(false, curve)
    {
      size_t n = deserialise_size_t(buf, sz);
      for (size_t i = 0; i < n; i++)
      {
        share_polynomials.push_back(SharePolynomials(buf, sz));
      }

      if (sz > 0)
      {
        n = deserialise_size_t(buf, sz);
        for (size_t i = 0; i < n; i++)
        {
          size_t m = deserialise_size_t(buf, sz);
          std::vector<EC::CompressedPoint> cs;
          for (size_t j = 0; j < m; j++)
          {
            size_t vs = deserialise_size_t(buf, sz);
            cs.push_back(EC::CompressedPoint(buf, buf + vs));
            assert(cs.back().size() == vs);
            buf += vs;
            sz -= vs;
          }
          commitments_.push_back(cs);
        }
      }
    }

    virtual ~ResharingDeal() {}

    virtual std::vector<uint8_t> serialise_shares() const override
    {
      std::vector<uint8_t> r = serialise_size_t(share_polynomials.size());
      for (auto& share : share_polynomials)
      {
        auto b = share.q.serialise();
        r.insert(r.end(), b.begin(), b.end());
        b = share.q_witness.serialise();
        r.insert(r.end(), b.begin(), b.end());
      }
      return r;
    }

    virtual std::vector<uint8_t> serialise_commitments() const override
    {
      std::vector<uint8_t> r;
      auto num_commitments = serialise_size_t(commitments_.size());
      r.insert(r.end(), num_commitments.begin(), num_commitments.end());

      for (auto& commit : commitments_)
      {
        auto commit_size = serialise_size_t(commit.size());
        r.insert(r.end(), commit_size.begin(), commit_size.end());
        for (auto& c : commit)
        {
          auto c_size = serialise_size_t(c.size());
          r.insert(r.end(), c_size.begin(), c_size.end());
          r.insert(r.end(), c.begin(), c.end());
        }
      }
      return r;
    }

    const std::vector<SharePolynomials>& shares() const
    {
      return share_polynomials;
    }

    const std::vector<std::vector<EC::CompressedPoint>>& commitments() const
    {
      // n*n compressed points
      return commitments_;
    }

    virtual std::string to_string() const override
    {
      return fmt::format(
        "sharings=[{}] shares=[{}] commitments=[{}]",
        fmt::join(sharings, ", "),
        fmt::join(share_polynomials, ", "),
        fmt::join(commitments_, ", "));
    }

  protected:
    size_t t, t_next;
    std::vector<std::shared_ptr<BivariatePolynomial>> sharings;
    std::vector<std::vector<EC::CompressedPoint>> commitments_;
    std::vector<SharePolynomials> share_polynomials;

    virtual void sample()
    {
      sharings.clear();
      auto q = BivariatePolynomial::sample_zss(t, t_next);
      auto q_witness = BivariatePolynomial::sample_zss(t, t_next);
      sharings.push_back(q);
      sharings.push_back(q_witness);

      LOG_TRACE_FMT(
        "SPLITID: resharing deal sharings q={} q_witness={}",
        q->to_string(),
        q_witness->to_string());
    }

    void compute_share_polynomials(const std::vector<size_t>& indices)
    {
      if (sharings.size() != 2)
      {
        throw std::logic_error("missing sharings");
      }

      share_polynomials.clear();

      const auto& q = sharings[0];
      const auto& q_witness = sharings[1];
      const auto& go = EC::curve_parameters[curve].order;
      for (auto i : indices)
      {
        BigNum index_i(i);
        auto share_poly_i = q->y_coefficients(index_i, go);
        auto witness_poly_i = q_witness->y_coefficients(index_i, go);
        LOG_TRACE_FMT(
          "SPLITID: share_polynomials for {}: [{}, {}]",
          i,
          share_poly_i.to_string(),
          witness_poly_i.to_string());

        share_polynomials.push_back(
          SharePolynomials({share_poly_i, witness_poly_i}));
      }
    }

    void compute_commits()
    {
      const auto& q = sharings[0];
      const auto& q_witness = sharings[1];
      size_t degree_y = q->coefficients.size();
      size_t degree_x = q->coefficients[0].size();

      commitments_.clear();

      for (size_t i = 0; i < degree_y; i++)
      {
        const auto& qv = q->coefficients[i];
        const auto& qv_witness = q_witness->coefficients[i];

        std::vector<EC::CompressedPoint> c;
        for (size_t j = 0; j < degree_x; j++)
        {
          c.push_back(compress_x_wx(qv[j], qv_witness[j], curve));
        }

        commitments_.push_back(c);
      }

      LOG_TRACE_FMT(
        "SPLITID: deal commitments: [{}]", fmt::join(commitments_, ", "));
    }
  };

  class SamplingDeal : public ResharingDeal
  {
  public:
    SamplingDeal(
      size_t t,
      const std::vector<size_t>& indices,
      bool defensive = false,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      ResharingDeal(t, t, indices, indices, curve, false)
    {
      sample();
      compute_share_polynomials(indices);
      compute_commits();
    }

    SamplingDeal(
      const uint8_t*& buf,
      size_t& sz,
      bool defensive = false,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      ResharingDeal(buf, sz, curve)
    {}

    virtual ~SamplingDeal() {}

    using ResharingDeal::t;

  protected:
    virtual void sample() override
    {
      sharings.clear();
      auto r = BivariatePolynomial::sample_rss(t, t);
      auto r_witness = BivariatePolynomial::sample_rss(t, t);
      sharings.push_back(r);
      sharings.push_back(r_witness);
    }
  };

  typedef struct
  {
    std::map<size_t, std::vector<uint8_t>> node_shares;
    std::vector<uint8_t> public_key;
    ZKP::CR zkp;
  } EncryptedShares;

  typedef struct
  {
    uint64_t id;
    EncryptedShares encrypted_shares;
    std::vector<std::vector<EC::CompressedPoint>> commitments;
  } EncryptedDeal;

  typedef struct
  {
    EncryptedShares encrypted_shares;
    std::vector<std::vector<EC::CompressedPoint>> batched_commits;
  } EncryptedResharing;

  typedef struct
  {
    EC::CompressedPoint x_share;
    ZKP::CR zkp;
  } OpenKey;

  typedef struct
  {
    EC::CompressedPoint k_share;
    ZKP::CR zkp;
  } OpenK;

  typedef struct
  {
    BigNum ak;
    BigNum s;
    ZKP::MultProof zkp;
  } SignatureShare;

  typedef struct
  {
    std::string id;
    std::vector<uint8_t> verifiable_symmetric_key;
  } Blame;

  template <typename NID>
  class Session
  {
  public:
    Session() :
      defensive(false),
      curve(EC::CurveID::SECP384R1),
      config({}),
      app_id(0)
    {}

    Session(
      const std::vector<NID>& config,
      bool defensive = false,
      uint64_t app_id = 0,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      defensive(defensive),
      curve(curve),
      config(config),
      app_id(app_id)
    {
      std::sort(this->config.begin(), this->config.end());
      for (auto& nid : this->config)
      {
        indices.push_back(get_node_index(nid));
        sharing_indices.push_back(get_sharing_index(nid));
      }
    }

    virtual ~Session() {}

    virtual size_t lower_threshold() const
    {
      size_t r = (config.size() + 2) / 3; // ~ t + 1
      return config.size() <= 3 ? 2 : r;
    }

    virtual size_t upper_threshold() const
    {
      size_t r = (2 * config.size() + 1) / 3; // ~ 2*t + 1
      return config.size() < 3 ? 2 : config.size() < 4 ? 3 : r;
    }

    bool defensive = false;
    EC::CurveID curve;

    std::vector<NID> config;
    std::vector<size_t> indices;
    std::vector<size_t> sharing_indices;
    uint64_t app_id;

    std::map<size_t, EncryptedDeal> encrypted_deals;
    std::map<size_t, EncryptedResharing> encrypted_reshares;

    size_t get_node_index(const NID& nid) const
    {
      size_t r = -1;
      for (auto& n : config)
      {
        r++;
        if (n == nid)
        {
          return r;
        }
      }
      throw std::logic_error(fmt::format("unknown nid {}", nid));
    }

    size_t get_sharing_index(const NID& nid) const
    {
      return get_node_index(nid) + 1;
    }

    virtual NID get_node_id(size_t node_index) const
    {
      if (node_index >= config.size())
        throw std::logic_error("invalid node index");
      return config[node_index];
    }

    EncryptedShares mk_encrypted_shares(
      const NID& nid,
      const Deal& deal,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      const std::vector<NID>& cfg,
      uint64_t deal_id) const
    {
      EncryptedShares r;

      KeyPair ephemeral_key_pair(curve);
      r.public_key = ephemeral_key_pair.public_key_pem;

      if (defensive)
      {
        auto bp = get_bignum_and_point(ephemeral_key_pair);
        r.zkp = ZKP::prove_exponent(bp.second, bp.first);
      }

      std::vector<uint8_t> iv(GCM_SIZE_IV, 0);
      for (size_t i = 0; i < GCM_SIZE_IV; i++)
      {
        iv[i] = i < 8 ? deal_id >> (i * 8) : 0;
      }

      for (auto onid : cfg)
      {
        auto plain = deal.serialise_shares();
        auto pkit = public_keys.find(onid);
        if (pkit == public_keys.end())
        {
          throw std::runtime_error(
            fmt::format("missing public key of {}", onid));
        }
        auto key = ephemeral_key_pair.derive_shared_secret(pkit->second);
        r.node_shares[get_node_index(onid)] = encrypt_buffer(key, iv, plain);
      }

      return r;
    }

    std::vector<uint8_t> decrypt_shares(
      size_t node_index,
      KeyPair& node_key,
      const std::vector<uint8_t>& shared_public_key,
      const EncryptedShares& encrypted_shares,
      uint64_t deal_id) const
    {
      std::vector<uint8_t> tag(GCM_SIZE_TAG, 0);

      std::vector<uint8_t> iv(GCM_SIZE_IV, 0);
      for (size_t i = 0; i < GCM_SIZE_IV; i++)
      {
        iv[i] = i < 8 ? deal_id >> (i * 8) : 0;
      }

      auto eit = encrypted_shares.node_shares.find(node_index);
      if (eit != encrypted_shares.node_shares.end())
      {
        auto key = node_key.derive_shared_secret(shared_public_key);
        return decrypt_buffer(key, iv, eit->second);
      }

      return {};
    }

    std::map<size_t, std::vector<uint8_t>> decrypt_deal_shares(
      size_t node_index,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      const std::map<size_t, EncryptedDeal>& encrypted_deals) const
    {
      std::map<size_t, std::vector<uint8_t>> r;
      for (const auto& [from, deal] : encrypted_deals)
      {
        r[from] = decrypt_shares(
          node_index,
          node_key,
          deal.encrypted_shares.public_key,
          deal.encrypted_shares,
          deal.id);
      }
      return r;
    }

    std::map<size_t, std::vector<uint8_t>> decrypt_resharings(
      size_t node_index,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      const std::map<size_t, EncryptedResharing>& encrypted_resharings) const
    {
      std::map<size_t, std::vector<uint8_t>> r;
      for (const auto& [from, resharing] : encrypted_resharings)
      {
        r[from] = decrypt_shares(
          node_index,
          node_key,
          resharing.encrypted_shares.public_key,
          resharing.encrypted_shares,
          0);
      }
      return r;
    }

    std::map<size_t, std::vector<std::vector<EC::CompressedPoint>>>
    get_deal_commitments(
      const std::map<size_t, EncryptedDeal>& encrypted_deals) const
    {
      std::map<size_t, std::vector<std::vector<EC::CompressedPoint>>> r;
      for (const auto& [from, encrypted_deal] : encrypted_deals)
      {
        r[from] = encrypted_deal.commitments;
      }
      return r;
    }
  };

  template <typename NID>
  struct NodeState;

  struct Identity
  {
    EC::CompressedPoint public_key;
    std::vector<EC::CompressedPoint> x_commits;
  };

  template <typename NID>
  class ResharingSession : public Session<NID>
  {
  public:
    ResharingSession() : Session<NID>({}, false, 0) {}

    ResharingSession(
      const Identity& previous_identity,
      const std::vector<NID>& config,
      const std::vector<NID>& next_config,
      bool defensive = false,
      uint64_t app_id = 0,
      EC::CurveID curve = EC::CurveID::SECP384R1) :
      Session<NID>(config, defensive, app_id, curve),
      next_config(next_config),
      previous_identity(previous_identity)
    {
      std::sort(this->next_config.begin(), this->next_config.end());
      for (auto& nid : this->next_config)
      {
        next_indices.push_back(get_node_index(nid, true));
        next_sharing_indices.push_back(get_sharing_index(nid, true));
      }
    }

    virtual ~ResharingSession() {}

    std::vector<NID> next_config;
    std::vector<size_t> next_indices;
    std::vector<size_t> next_sharing_indices;
    std::vector<std::vector<EC::CompressedPoint>> batched_commits;
    Identity previous_identity;

    using Session<NID>::curve;
    using Session<NID>::config;
    using Session<NID>::indices;
    using Session<NID>::sharing_indices;
    using Session<NID>::defensive;
    using Session<NID>::encrypted_deals;
    using Session<NID>::encrypted_reshares;
    using Session<NID>::decrypt_deal_shares;
    using Session<NID>::decrypt_resharings;
    using Session<NID>::get_deal_commitments;
    using Session<NID>::lower_threshold;
    using Session<NID>::upper_threshold;
    using Session<NID>::mk_encrypted_shares;

    virtual size_t lower_threshold_next() const
    {
      size_t r = (next_config.size() + 2) / 3; // ~ t + 1
      return next_config.size() <= 3 ? 2 : r;
    }

    virtual size_t upper_threshold_next() const
    {
      size_t r = (2 * next_config.size() + 1) / 3; // ~ 2*t + 1
      return next_config.size() < 4 ? 3 : r;
    }

    size_t get_node_index(const NID& nid, bool next = false) const
    {
      size_t r = -1;
      auto& cfg = next ? next_config : config;
      for (auto& n : cfg)
      {
        r++;
        if (n == nid)
        {
          return r;
        }
      }
      throw std::logic_error(fmt::format("unknown nid {}", nid));
    }

    size_t get_sharing_index(const NID& nid, bool next = false) const
    {
      return get_node_index(nid, next) + 1;
    }

    virtual NID get_node_id(size_t node_index, bool next = false) const
    {
      if (next && node_index >= next_config.size())
        throw std::logic_error("invalid node index");
      return next ? next_config[node_index] :
                    Session<NID>::get_node_id(node_index);
    }

    void add_deal(const NID& from, const EncryptedDeal& encrypted_deal)
    {
      LOG_DEBUG_FMT("SPLITID: adding deal from {}", from);

      if (
        std::find(config.begin(), config.end(), from) == config.end() &&
        std::find(next_config.begin(), next_config.end(), from) ==
          next_config.end())
        throw std::logic_error("Unsolicited deal");

      if (encrypted_deals.find(get_node_index(from)) != encrypted_deals.end())
      {
        return;
        // throw std::logic_error("Duplicate deal");
      }

      if (encrypted_deal.encrypted_shares.node_shares.size() != config.size())
        throw std::logic_error("Incomplete deal");

      for (const auto& nid : config)
      {
        const auto& node_shares = encrypted_deal.encrypted_shares.node_shares;
        if (node_shares.find(get_node_index(nid)) == node_shares.end())
        {
          throw std::logic_error(
            fmt::format("Incomplete deal; missing node: {}", nid));
        }
      }

      if (encrypted_deals.size() >= lower_threshold())
      {
        LOG_DEBUG_FMT(
          "SPLITID: dropping superfluous deal from {} (have {}/{})",
          from,
          encrypted_deals.size(),
          lower_threshold());
        return;
      }

      encrypted_deals[get_node_index(from)] = encrypted_deal;
    }

    void add_resharing(
      const NID& from, const EncryptedResharing& encrypted_resharing)
    {
      LOG_DEBUG_FMT("SPLITID: adding resharing from {}", from);
      size_t from_index = get_node_index(from);

      if (std::find(config.begin(), config.end(), from) == config.end())
        throw std::logic_error("Unsolicited resharing");

      if (encrypted_reshares.find(from_index) != encrypted_reshares.end())
      {
        return;
      }

      if (
        encrypted_resharing.encrypted_shares.node_shares.size() !=
        next_config.size())
        throw std::logic_error("Incomplete resharing");

      for (const auto& nid : config)
      {
        if (
          encrypted_resharing.encrypted_shares.node_shares.find(from_index) ==
          encrypted_resharing.encrypted_shares.node_shares.end())
        {
          throw std::logic_error(
            fmt::format("Incomplete resharing; missing node: {}", nid));
        }
      }

      if (encrypted_reshares.size() >= upper_threshold())
      {
        LOG_DEBUG_FMT("SPLITID: dropping superfluous resharing from {}", from);
        return;
      }

      encrypted_reshares[from_index] = encrypted_resharing;

      LOG_TRACE_FMT(
        "SPLITID: {}: batched_commits: {} encrypted_reshare.batched_commits: "
        "{}",
        from,
        batched_commits,
        encrypted_resharing.batched_commits);

      if (batched_commits.empty())
      {
        LOG_TRACE_FMT("SPLITID: writing batched_commits into session object");
        batched_commits = encrypted_resharing.batched_commits;
      }
      else
      {
        if (batched_commits != encrypted_resharing.batched_commits)
          throw std::runtime_error("mismatch of batched commitments");
      }
    }

    void compute_x_wx_shares(
      const NID& nid,
      const std::vector<EC::CompressedPoint>& x_commits,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      BigNum& x,
      BigNum& x_witness) const
    {
      LOG_DEBUG_FMT(
        "SPLITID: {}: compute_x_wx_shares batched_commits: {} x_commits: {}",
        nid,
        batched_commits,
        x_commits);

      const auto& go = EC::curve_parameters[curve].order;

      std::vector<BigNum> shares, witnesses;
      std::vector<size_t> indices;

      size_t idx = get_node_index(nid, true);
      auto decrypted_resharings =
        decrypt_resharings(idx, node_key, public_keys, encrypted_reshares);
      for (const auto& [from, resharing] : decrypted_resharings)
      {
        assert(resharing.size() > 0);

        auto onid = get_node_id(from);
        const uint8_t* data = resharing.data();
        size_t sz = resharing.size();

        BigNum x_jk(data, sz);
        BigNum wx_jk(data, sz);

        LOG_TRACE_FMT(
          "SPLITID: {}: resharing from {}: x_jk={} wx_jk={}",
          nid,
          onid,
          x_jk,
          wx_jk);
        verify_transfer_shares(
          batched_commits, x_commits, nid, onid, x_jk, wx_jk);
        shares.push_back(x_jk);
        witnesses.push_back(wx_jk);
        indices.push_back(get_sharing_index(onid, false));

        if (shares.size() >= lower_threshold())
        {
          x = BigNum::lagrange_interpolate(shares, indices, BigNum::zero(), go);
          assert(x != BigNum::zero());
          x_witness = BigNum::lagrange_interpolate(
            witnesses, indices, BigNum::zero(), go);
          assert(x_witness != BigNum::zero());
          LOG_TRACE_FMT(
            "SPLITID: {}: key share and witness successfully interpolated",
            nid);
          break;
        }
      }
    }

    void verify_transfer_shares(
      const std::vector<std::vector<EC::CompressedPoint>>& batched_commits,
      const std::vector<EC::CompressedPoint>& x_commits,
      const NID& nid,
      const NID& onid,
      const BigNum& x_jk,
      const BigNum& wx_jk) const
    {
      size_t j = get_sharing_index(onid, false);
      size_t k = get_sharing_index(nid, true);
      LOG_TRACE_FMT(
        "SPLITID: {}: verifying transfer shares {} -> {}: batched_commits: {} "
        "x_commits: {} j={} k={}",
        nid,
        onid,
        nid,
        batched_commits,
        x_commits,
        j,
        k);
      std::vector<EC::CompressedPoint> qj_commits;
      for (auto& q : batched_commits)
      {
        auto q_eval = EC::eval_in_exp(q, j, EC::curve_parameters[curve].order);
        qj_commits.push_back(q_eval.compress());
      }
      auto eval1 =
        EC::eval_in_exp(x_commits, j, EC::curve_parameters[curve].order);
      auto eval2 =
        EC::eval_in_exp(qj_commits, k, EC::curve_parameters[curve].order);
      auto computed = eval1.add(eval2).compress();
      auto received = compress_x_wx(x_jk, wx_jk);
      LOG_DEBUG_FMT("{} =?= {}", computed, received);
      if (computed != received)
      {
        throw std::runtime_error("invalid commitment");
      }
    }

    void update_commitments(
      const NID& nid,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      BigNum& x,
      BigNum& x_witness,
      Identity& node_identity) const
    {
      if (batched_commits.empty())
      {
        throw std::runtime_error(fmt::format("missing batched commitments"));
      }

      LOG_TRACE_FMT(
        "SPLITID: {}: update commitments previous x_commits: {} "
        "node_identity.x_commits: {}",
        nid,
        previous_identity.x_commits,
        node_identity.x_commits);

      compute_x_wx_shares(
        nid, previous_identity.x_commits, node_key, public_keys, x, x_witness);

      std::vector<EC::CompressedPoint> updated_x_commits =
        previous_identity.x_commits;
      update_x_commits(nid, batched_commits, updated_x_commits);

      LOG_TRACE_FMT(
        "SPLITID: {}: updated_x_commits: {}", nid, updated_x_commits);

      auto k = get_sharing_index(nid, true);
      auto received =
        EC::eval_in_exp(updated_x_commits, k, EC::curve_parameters[curve].order)
          .compress();
      auto recomputed = compress_x_wx(x, x_witness);
      if (received != recomputed)
      {
        throw std::logic_error("invalid commitments");
      }

      node_identity.x_commits = updated_x_commits;

      if (node_identity.public_key.empty())
      {
        node_identity.public_key = previous_identity.public_key;
      }
    }

    EncryptedDeal mk_deal(
      const NID& nid,
      const KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      uint64_t deal_id) const
    {
      LOG_DEBUG_FMT(
        "SPLITID: {}: resharing mk_deal lower: {} lower next: {}",
        nid,
        lower_threshold(),
        lower_threshold_next());
      size_t t = lower_threshold() - 1; // want sharing_indices.size() - 1 // 3
      size_t t_next = lower_threshold_next() - 1;
      if (t == 0)
        t++;
      if (t_next == 0)
        t_next++;
      ResharingDeal deal(t, t_next, sharing_indices, next_sharing_indices);
      EncryptedDeal r;
      r.encrypted_shares =
        mk_encrypted_shares(nid, deal, public_keys, config, deal_id);
      r.commitments = deal.commitments();
      r.id = deal_id;
      return r;
    }

    std::vector<std::vector<BigNum>> sum_polynomials(
      const NID& nid,
      const std::map<size_t, std::vector<uint8_t>>& decrypted_shares) const
    {
      if (decrypted_shares.empty())
      {
        throw std::logic_error("no decrypted shares");
      }

      std::vector<SharePolynomials> polys;
      auto index = get_node_index(nid);
      for (auto& [from, ds] : decrypted_shares)
      {
        const uint8_t* data = ds.data();
        size_t sz = ds.size();
        ResharingDeal d(data, sz);
        auto share_i = d.shares()[index];
        polys.push_back(share_i);
      }

      return sum_share_polys(polys, EC::curve_parameters[curve].order);
    }

    void batch_commits(
      const NID& nid,
      const std::map<size_t, std::vector<std::vector<EC::CompressedPoint>>>&
        commitments,
      std::vector<std::vector<EC::CompressedPoint>>& batched_commits) const
    {
      if (commitments.size() != lower_threshold())
      {
        throw std::logic_error("incorrect number of deals");
      }

      for (const auto& [from, cs] : commitments)
      {
        LOG_TRACE_FMT(
          "SPLITID: {}: batch_commits onid: {} from: {} cs: {}",
          nid,
          config[from],
          from,
          cs);
      }

      batched_commits.clear();

      size_t y_dim = commitments.size();
      assert(y_dim > 0);
      size_t x_dim = commitments.begin()->second.size();
      assert(x_dim > 0);

      for (size_t y = 0; y < y_dim; y++)
      {
        std::vector<EC::CompressedPoint> xt;
        for (size_t x = 0; x < x_dim; x++)
        {
          EC::Point p(EC::CurveID::SECP384R1);
          for (const auto& [from, ci] : commitments)
          {
            assert(!ci.empty());
            assert(y < ci.size());
            assert(x < ci[0].size());
            p = p.add(EC::Point(ci[y][x]));
          }
          xt.push_back(p.compress());
        }
        batched_commits.push_back(xt);
      }

      assert(batched_commits.size() == commitments.size());

      LOG_TRACE_FMT("SPLITID: {}: batched commits: {}", nid, batched_commits);
    }

    virtual void update_x_commits(
      const NID& nid,
      const std::vector<std::vector<EC::CompressedPoint>>& batched_commits,
      std::vector<EC::CompressedPoint>& x_commits) const
    {
      assert(x_commits.size() > 0);
      x_commits.resize(1); // x_commits[0] stays
      for (size_t i = 1; i < batched_commits.size(); i++)
      {
        x_commits.push_back(batched_commits[i][0]);
      }
    }

    EncryptedResharing mk_resharing(
      const NID& nid,
      const BigNum& x,
      const BigNum& x_witness,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      std::map<NID, uint64_t>& max_deal_ids_seen) const
    {
      if (encrypted_deals.size() < lower_threshold())
      {
        throw std::runtime_error(fmt::format(
          "invalid number of deals: {}, expected at least {}",
          encrypted_deals.size(),
          lower_threshold()));
      }

      for (const auto& [from, ed] : encrypted_deals)
      {
        auto from_nid = get_node_id(from);
        auto dit = max_deal_ids_seen.find(from_nid);
        if (dit != max_deal_ids_seen.end() && dit->second > ed.id)
        {
          throw std::runtime_error("at risk of re-using a deal, abort session");
        }
        max_deal_ids_seen.emplace(from_nid, ed.id);
      }

      if (defensive)
      {
        for (const auto& [from, ed] : encrypted_deals)
        {
          auto public_pnt =
            get_public_point_from_pem(ed.encrypted_shares.public_key);
          if (!ZKP::verify_exponent(public_pnt, ed.encrypted_shares.zkp))
          {
            throw std::runtime_error(fmt::format(
              "{}: verification of deal proof from {} failed",
              nid,
              get_node_id(from, false)));
          }
        }
      }

      auto decrypted_shares = decrypt_deal_shares(
        get_node_index(nid), node_key, public_keys, encrypted_deals);
      auto commitments = get_deal_commitments(encrypted_deals);

      if (decrypted_shares.size() != encrypted_deals.size())
      {
        throw std::runtime_error("deal shares and commitments sizes mismatch");
      }

      EncryptedResharing r;

      std::vector<std::vector<EC::CompressedPoint>> batched_commits;
      batch_commits(nid, commitments, batched_commits);
      assert(batched_commits.size() > 0);
      auto sum = sum_polynomials(nid, decrypted_shares);

      try
      {
        verify_shares(nid, sum, batched_commits);
      }
      catch (std::exception& ex)
      {
        throw std::runtime_error("share verification failed; blame NYI");
      }

      assert(sum.size() == 2);
      auto share_polynomial = Polynomial(sum[0]);
      auto witness_polynomial = Polynomial(sum[1]);
      auto go = EC::curve_parameters[curve].order;
      std::vector<uint8_t> iv(GCM_SIZE_IV, 0);
      std::vector<uint8_t> tag(GCM_SIZE_TAG, 0);

      KeyPair ephemeral_key_pair(curve);
      r.encrypted_shares.public_key = ephemeral_key_pair.public_key_pem;

      for (auto onid : next_config)
      {
        BigNum idx(get_sharing_index(onid, true));

        auto x_eval = share_polynomial.eval(idx, go);
        auto x_jk = BigNum::mod_add(x, x_eval, go);

        auto w_eval = witness_polynomial.eval(idx, go);
        auto wx_jk = BigNum::mod_add(x_witness, w_eval, go);

        LOG_TRACE_FMT(
          "SPLITID: reshare of {} for {}: x_jk={} wx_jk={}",
          nid,
          onid,
          x_jk,
          wx_jk);

        auto xks = x_jk.serialise();
        auto wks = wx_jk.serialise();

        std::vector<uint8_t> ris;
        ris.insert(ris.end(), xks.begin(), xks.end());
        ris.insert(ris.end(), wks.begin(), wks.end());

        auto pkit = public_keys.find(onid);
        if (pkit == public_keys.end())
        {
          throw std::runtime_error(
            fmt::format("missing public key of {}", onid));
        }
        auto key = ephemeral_key_pair.derive_shared_secret(pkit->second);
        r.encrypted_shares.node_shares[get_node_index(onid, true)] =
          encrypt_buffer(key, iv, ris);
      }

      r.batched_commits = batched_commits;

      return r;
    }

    void verify_shares(
      const NID& nid,
      const std::vector<std::vector<BigNum>>& share_polynomials,
      const std::vector<std::vector<EC::CompressedPoint>>& batched_commits)
      const
    {
      LOG_TRACE_FMT(
        "SPLITID: {}: verify_shares batched_commits: {}", nid, batched_commits);

      if (batched_commits.empty())
      {
        throw std::runtime_error("missing batched commitments");
      }

      size_t degree_y = batched_commits.size();
      size_t degree_x = batched_commits[0].size();
      auto shares = share_polynomials[0];
      auto witnesses = share_polynomials[1];

      LOG_TRACE_FMT(
        "SPLITID: {}: verify_shares degree_x: {} degree_y: {}",
        nid,
        degree_x,
        degree_y);

      auto index = get_sharing_index(nid, false);
      for (size_t i = 0; i < degree_y; i++)
      {
        // Recompute commitment from received shares and check that they match.
        EC::CompressedPoint computed =
          EC::eval_in_exp(
            batched_commits[i], index, EC::curve_parameters[curve].order)
            .compress();
        auto received = compress_x_wx(shares[i], witnesses[i]);
        if (computed != received)
        {
          throw std::logic_error("shares do not correspond to commitments");
        }
      }
    }
  };

  template <typename NID>
  class SamplingSession : public ResharingSession<NID>
  {
  public:
    SamplingSession() : ResharingSession<NID>({}, {}, {}, false, 0) {}

    SamplingSession(
      const std::vector<NID>& config,
      bool defensive = false,
      uint64_t app_id = 0) :
      ResharingSession<NID>(Identity(), config, config, defensive, app_id)
    {}

    virtual ~SamplingSession() {}

    using ResharingSession<NID>::curve;
    using ResharingSession<NID>::config;
    using ResharingSession<NID>::next_config;
    using ResharingSession<NID>::indices;
    using ResharingSession<NID>::next_indices;
    using ResharingSession<NID>::sharing_indices;
    using ResharingSession<NID>::defensive;
    using ResharingSession<NID>::batched_commits;
    using ResharingSession<NID>::get_sharing_index;
    using ResharingSession<NID>::get_node_index;
    using ResharingSession<NID>::get_node_id;
    using ResharingSession<NID>::decrypt_deal_shares;
    using ResharingSession<NID>::decrypt_resharings;
    using ResharingSession<NID>::get_deal_commitments;
    using ResharingSession<NID>::compute_x_wx_shares;
    using ResharingSession<NID>::encrypted_deals;
    using ResharingSession<NID>::encrypted_reshares;
    using ResharingSession<NID>::mk_encrypted_shares;
    using ResharingSession<NID>::lower_threshold;
    using ResharingSession<NID>::upper_threshold;
    using ResharingSession<NID>::verify_shares;
    using ResharingSession<NID>::mk_resharing;
    using ResharingSession<NID>::batch_commits;
    using ResharingSession<NID>::sum_polynomials;
    using ResharingSession<NID>::add_deal;
    using ResharingSession<NID>::add_resharing;

    std::map<size_t, OpenKey> open_keys;

    EncryptedDeal mk_deal(
      const NID& nid,
      const KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      uint64_t deal_id) const
    {
      SamplingDeal deal(lower_threshold() - 1, sharing_indices, defensive);
      EncryptedDeal r;
      r.encrypted_shares =
        mk_encrypted_shares(nid, deal, public_keys, config, deal_id);
      r.commitments = deal.commitments();
      r.id = deal_id;
      return r;
    }

    virtual void update_x_commits(
      const NID& nid,
      const std::vector<std::vector<EC::CompressedPoint>>& batched_commits,
      std::vector<EC::CompressedPoint>& x_commits) const override
    {
      x_commits.clear();
      for (size_t i = 0; i < batched_commits.size(); i++)
      {
        x_commits.push_back(batched_commits[i][0]);
      }
    }

    void compute_private_shares(
      const NID& nid,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      BigNum& x,
      BigNum& x_witness,
      std::vector<EC::CompressedPoint>& x_commits) const
    {
      bool xc_all_zero = true;
      for (const auto& xci : x_commits)
      {
        xc_all_zero &= xci.empty() || xci[0] == 0;
      }

      if (xc_all_zero)
      {
        size_t t = lower_threshold() - 1;
        if (t == 0)
          t = 1;

        x_commits.resize(t);
        for (size_t i = 0; i < t; i++)
        {
          x_commits.push_back({0});
        }

        compute_x_wx_shares(
          nid, x_commits, node_key, public_keys, x, x_witness);
        update_x_commits(nid, batched_commits, x_commits);
        LOG_TRACE_FMT("SPLITID: {}: new x_commits: {}", nid, x_commits);
      }
    }

    OpenKey mk_open_key(
      const NID& nid,
      BigNum& x,
      BigNum& x_witness,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      std::vector<EC::CompressedPoint>& x_commits) const
    {
      if (encrypted_reshares.size() < upper_threshold())
      {
        throw std::runtime_error(fmt::format(
          "invalid number of reshares: {}, expected {}",
          encrypted_reshares.size(),
          upper_threshold()));
      }

      if (batched_commits.empty())
      {
        throw std::runtime_error(fmt::format("missing batched commits"));
      }

      compute_private_shares(
        nid, node_key, public_keys, x, x_witness, x_commits);

      OpenKey r;
      r.x_share = EC::curve_parameters[curve].G.mul(x).compress();
      auto c_share = compressed_commit_multi(0, {x, x_witness});
      r.zkp = ZKP::prove_openk({r.x_share, c_share}, {x, x_witness}, 0);
      return r;
    }

    void check_open_key(
      const NID& nid,
      const OpenKey& ok,
      const std::vector<EC::CompressedPoint>& x_commits) const
    {
      size_t j = get_sharing_index(nid);
      auto Cj = compute_c_at_j(x_commits, j);
      if (!ZKP::verify_openk({ok.x_share, Cj}, ok.zkp, 0))
      {
        throw std::runtime_error("verification of openk proof failed");
      }
    }

    std::string compute_public_key(
      const NID& nid,
      std::vector<EC::CompressedPoint>& x_commits,
      EC::CompressedPoint& X) const
    {
      if (open_keys.size() < lower_threshold())
      {
        throw std::runtime_error(fmt::format(
          "invalid number of open_keys: {}, expected {}",
          open_keys.size(),
          lower_threshold()));
      }

      update_x_commits(nid, batched_commits, x_commits);

      std::vector<size_t> X_indices;
      std::vector<EC::CompressedPoint> X_shares;
      for (auto& [nix, ok] : open_keys)
      {
        check_open_key(get_node_id(nix), ok, x_commits);
        X_indices.push_back(get_sharing_index(get_node_id(nix)));
        X_shares.push_back(ok.x_share);
      }

      X = lagrange_in_exp_feldman(X_shares, X_indices, BigNum::zero());

      auto pem = EC::Point(X).to_public_pem();
      LOG_DEBUG_FMT("SPLITID: computed public key: {}", pem);
      return pem;
    }

    void add_open_key(const NID& from, const OpenKey& open_key)
    {
      LOG_DEBUG_FMT("SPLITID: adding open_key from {}", from);
      size_t from_index = get_node_index(from);

      if (
        std::find(next_config.begin(), config.end(), from) == next_config.end())
        throw std::logic_error("Unsolicited open_key");

      if (open_keys.find(from_index) != open_keys.end())
      {
        return;
        // throw std::logic_error("Duplicate open_key");
      }

      if (open_keys.size() >= lower_threshold())
      {
        LOG_DEBUG_FMT(
          "SPLITID: dropping superfluous open_key from {} (have {}/{})",
          from,
          open_keys.size(),
          lower_threshold());
        return;
      }

      open_keys[from_index] = open_key;
    }
  };

  template <typename NID>
  class SigningSession : public Session<NID>
  {
  public:
    SigningSession() : Session<NID>({}, false, 0) {}

    SigningSession(
      const std::vector<NID>& config,
      const std::vector<uint8_t>& message,
      bool defensive = false,
      uint64_t app_id = 0) :
      Session<NID>(config, defensive, app_id),
      message(message)
    {}

    using Session<NID>::curve;
    using Session<NID>::config;
    using Session<NID>::indices;
    using Session<NID>::sharing_indices;
    using Session<NID>::defensive;
    using Session<NID>::get_node_index;
    using Session<NID>::get_sharing_index;
    using Session<NID>::decrypt_deal_shares;
    using Session<NID>::get_deal_commitments;
    using Session<NID>::encrypted_deals;
    using Session<NID>::mk_encrypted_shares;
    using Session<NID>::lower_threshold;
    using Session<NID>::upper_threshold;
    using Session<NID>::get_node_id;

    std::vector<uint8_t> message; // message to be signed

    std::map<NID, OpenK> openks;
    std::map<NID, SignatureShare> signature_shares;
    std::vector<uint8_t> signature; // DER encoded signature

    EncryptedDeal mk_deal(
      const NID& nid,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      uint64_t deal_id) const
    {
      size_t lt = lower_threshold();
      size_t lower_degree = config.size() <= 3 ? 1 : lt - 1;
      SigningDeal deal(
        lower_degree, upper_threshold(), sharing_indices, defensive);
      EncryptedDeal r;
      r.encrypted_shares =
        mk_encrypted_shares(nid, deal, public_keys, config, deal_id);
      r.commitments = {deal.commitments()};
      r.id = deal_id;
      return r;
    }

    void add_deal(const NID& from, const EncryptedDeal& encrypted_deal)
    {
      LOG_DEBUG_FMT("SPLITID: adding deal from {}", from);
      size_t from_index = get_node_index(from);

      if (std::find(config.begin(), config.end(), from) == config.end())
      {
        throw std::logic_error("Unsolicited deal");
      }

      if (encrypted_deals.find(from_index) != encrypted_deals.end())
      {
        return;
      }

      if (encrypted_deal.encrypted_shares.node_shares.size() != config.size())
      {
        throw std::logic_error("Incomplete deal");
      }

      for (const auto& nid : config)
      {
        const auto& node_shares = encrypted_deal.encrypted_shares.node_shares;
        if (node_shares.find(get_node_index(nid)) == node_shares.end())
        {
          throw std::logic_error(
            fmt::format("Incomplete deal; missing node: {}", nid));
        }
      }

      if (encrypted_deals.size() >= lower_threshold())
      {
        LOG_DEBUG_FMT(
          "SPLITID: dropping superfluous deal from {} (have {}/{})",
          from,
          encrypted_deals.size(),
          lower_threshold());
        return;
      }

      encrypted_deals[from_index] = encrypted_deal;
    }

    std::vector<BigNum> sum_shares(
      const NID& nid,
      const std::map<size_t, std::vector<uint8_t>>& decrypted_deals) const
    {
      if (decrypted_deals.size() == 0)
      {
        throw std::logic_error("no decrypted shares/deals");
      }

      std::vector<BigNum> r;
      auto go = EC::curve_parameters[curve].order;
      size_t index = get_node_index(nid);

      for (auto& [_, ds] : decrypted_deals)
      {
        const uint8_t* data = ds.data();
        size_t sz = ds.size();
        SigningDeal d(data, sz);
        auto dshares = d.shares();
        assert(dshares.size() > index);

        if (r.size() == 0)
        {
          r.resize(dshares[index].size());
          for (size_t i = 0; i < r.size(); i++)
          {
            r[i] = BigNum::make_zero();
          }
        }

        for (size_t i = 0; i < r.size(); i++)
        {
          r[i] = BigNum::mod_add(r[i], dshares[index][i], go);
        }
      }

      return r;
    }

    void batch_commits(
      const NID& nid,
      const std::map<size_t, std::vector<std::vector<EC::CompressedPoint>>>&
        commitments,
      std::vector<EC::CompressedPoint>& batched_commits) const
    {
      if (commitments.size() != lower_threshold())
      {
        throw std::logic_error("incorrect number of commitments");
      }

      batched_commits.clear();

      size_t y_dim = commitments.size();
      assert(y_dim > 0);
      size_t x_dim = commitments.begin()->second.size();
      assert(x_dim > 0);

      for (size_t i = 0; i < upper_threshold(); i++)
      {
        EC::Point c;
        for (const auto& [from, vector] : commitments)
        {
          if (vector.size() != 1)
          {
            throw std::runtime_error("unexpected commitment vector size");
          }
          if (vector[0].empty())
          {
            continue;
          }
          c = c.add(EC::Point(vector[0][i]));
        }
        batched_commits.push_back(c.compress());
      }
    }

    void verify_shares(
      const NID& nid,
      size_t j,
      const std::vector<BigNum>& shares,
      const std::vector<EC::CompressedPoint>& commits) const
    {
      LOG_TRACE_FMT(
        "SPLITID: {}: verify_shares batched_commits: {}", nid, commits);
      auto received = compute_c_at_j(commits, j);
      auto computed = EC::commit_multi(2, shares).compress();
      if (computed != received)
      {
        throw std::logic_error("shares do not correspond to commitments");
      }
    }

    OpenK mk_openk(
      const NID& nid,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      std::map<NID, uint64_t>& max_deal_ids_seen) const
    {
      if (encrypted_deals.size() != lower_threshold())
      {
        throw std::runtime_error(fmt::format(
          "invalid number of deals: {}, expected {}",
          encrypted_deals.size(),
          lower_threshold()));
      }

      for (const auto& [from, ed] : encrypted_deals)
      {
        auto from_nid = get_node_id(from);
        auto dit = max_deal_ids_seen.find(from_nid);
        if (dit != max_deal_ids_seen.end() && dit->second > ed.id)
        {
          throw std::runtime_error("at risk of re-using a deal, abort session");
        }
        max_deal_ids_seen.emplace(from_nid, ed.id);
      }

      auto decrypted_shares = decrypt_deal_shares(
        get_node_index(nid), node_key, public_keys, encrypted_deals);
      auto commitments = get_deal_commitments(encrypted_deals);

      std::vector<BigNum> share_sums = sum_shares(nid, decrypted_shares);

      if (defensive)
      {
        std::vector<EC::CompressedPoint> batched_commits;
        batch_commits(nid, commitments, batched_commits);
        verify_shares(nid, get_sharing_index(nid), share_sums, batched_commits);
      }

      assert(share_sums.size() > 0);
      OpenK r;

      auto k = share_sums[0];
      r.k_share = EC::curve_parameters[curve].G.mul(k).compress();
      if (defensive)
      {
        auto c_share = EC::commit_multi(2, share_sums).compress();
        r.zkp = ZKP::prove_openk({r.k_share, c_share}, share_sums);
      }
      return r;
    }

    void add_openk(const NID& from, const OpenK& openk)
    {
      LOG_DEBUG_FMT("SPLITID: adding openk from {}", from);

      if (std::find(config.begin(), config.end(), from) == config.end())
        throw std::logic_error("Unsolicited deal");

      if (openks.find(from) != openks.end())
      {
        return;
        // throw std::logic_error("Duplicate deal");
      }

      size_t threshold = defensive ? lower_threshold() : upper_threshold();

      if (openks.size() >= threshold)
      {
        LOG_DEBUG_FMT(
          "SPLITID: dropping superfluous openk from {} (have {}/{})",
          from,
          openks.size(),
          threshold);
        return;
      }

      openks[from] = openk;
    }

    void add_signature_share(
      const NID& from, const SignatureShare& signature_share)
    {
      LOG_DEBUG_FMT("SPLITID: adding signature share from {}", from);

      if (std::find(config.begin(), config.end(), from) == config.end())
        throw std::logic_error("Unsolicited signature share");

      if (signature_shares.find(from) != signature_shares.end())
      {
        return;
        // throw std::logic_error("Duplicate signature share");
      }

      if (signature_shares.size() >= upper_threshold())
      {
        LOG_DEBUG_FMT(
          "SPLITID: dropping superfluous signature share from {} (have {}/{})",
          from,
          signature_shares.size(),
          upper_threshold());
        return;
      }

      signature_shares[from] = signature_share;
    }

    void check_openk(
      const NID& nid,
      const OpenK& ok,
      const std::vector<EC::CompressedPoint>& batched_commits) const
    {
      size_t j = get_sharing_index(nid);
      auto cj = compute_c_at_j(batched_commits, j);
      if (!ZKP::verify_openk({ok.k_share, cj}, ok.zkp))
      {
        throw std::runtime_error("verification of openk proof failed");
      }
    }

    EC::CompressedPoint interpolate_and_check(
      const std::vector<EC::CompressedPoint>& shares,
      const std::vector<size_t>& indices) const
    {
      assert(shares.size() == indices.size());
      assert(shares.size() >= upper_threshold());

      size_t lt = lower_threshold() + (config.size() < 4 ? 1 : 0);
      std::vector<EC::CompressedPoint> shares_head;
      std::vector<size_t> indices_head;
      for (size_t i = 0; i < lt; i++)
      {
        shares_head.push_back(shares[i]);
        indices_head.push_back(indices[i]);
      }

      for (size_t i = lt; i < shares.size(); i++)
      {
        auto interpolated =
          lagrange_in_exp_feldman(shares_head, indices_head, indices[i]);
        if (shares[i] != interpolated)
        {
          throw std::runtime_error("inconsistent shares");
        }
      }

      return lagrange_in_exp_feldman(shares_head, indices_head, BigNum::zero());
    }

    BigNum interpolate_x(
      const std::map<size_t, EncryptedDeal>& encrypted_deals) const
    {
      std::vector<size_t> indices;
      std::vector<EC::CompressedPoint> shares;
      for (auto& [nid, ok] : openks)
      {
        indices.push_back(get_sharing_index(nid));
        shares.push_back(ok.k_share);

        if (defensive)
        {
          std::vector<EC::CompressedPoint> batched_commits;
          auto commitments = get_deal_commitments(encrypted_deals);
          batch_commits(nid, commitments, batched_commits);
          check_openk(nid, ok, batched_commits);
        }
      }

      EC::CompressedPoint k;
      if (defensive)
      {
        k = lagrange_in_exp_feldman(shares, indices, BigNum::zero());
      }
      else
      {
        k = interpolate_and_check(shares, indices);
      }

      return EC::Point(k).x();
    }

    SignatureShare mk_signature_share(
      const NID& nid,
      const BigNum& x,
      const BigNum& x_witness,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      BigNum& r) const
    {
      const auto& go = EC::curve_parameters[curve].order;
      size_t threshold = defensive ? lower_threshold() : upper_threshold();

      if (openks.size() < threshold)
      {
        throw std::runtime_error(fmt::format(
          "invalid number of openks: {}, expected {}",
          openks.size(),
          threshold));
      }

      auto decrypted_shares = decrypt_deal_shares(
        get_node_index(nid), node_key, public_keys, encrypted_deals);
      r = interpolate_x(encrypted_deals);

      auto m = BigNum(hash(message));

      std::vector<BigNum> share_sums = sum_shares(nid, decrypted_shares);
      assert(share_sums.size() == 4 || defensive && share_sums.size() == 5);
      const auto& k = share_sums[0];
      const auto& a = share_sums[1];
      const auto& z = share_sums[2];
      const auto& y = share_sums[3];

      SignatureShare result;

      result.ak = a.mod_mul(k, go).mod_add(z, go);
      result.s = a.mod_mul(r.mod_mul(x, go).mod_add(m, go), go).mod_add(y, go);

      if (defensive)
      {
        std::vector<BigNum> pv = {x, x_witness};
        pv.insert(pv.end(), share_sums.begin(), share_sums.end());
        result.zkp = ZKP::prove_mult(m, r, result.ak, result.s, pv);
      }

      return result;
    }

    void check_signature_share(
      const NID& nid,
      const NID& onid,
      const SignatureShare& ss,
      const BigNum& r,
      const std::vector<EC::CompressedPoint>& x_commits,
      const std::vector<EC::CompressedPoint>& batched_commits) const
    {
      LOG_TRACE_FMT(
        "SPLITID: {}: check_signature_share batched_commits: {} x_commits: {}",
        nid,
        batched_commits,
        x_commits);
      auto j = get_sharing_index(onid);
      auto mp = hash(message);
      auto cy_pv = EC::Point(compute_c_at_j(x_commits, j))
                     .add(EC::Point(compute_c_at_j(batched_commits, j)))
                     .compress();
      if (!ZKP::verify_mult(cy_pv, mp, r, ss.ak, ss.s, ss.zkp))
      {
        throw std::runtime_error(
          "verification of signature share proof failed");
      }
    }

    bool check_signature(
      const std::vector<uint8_t>& sig, const EC::CompressedPoint& X) const
    {
      auto h = hash(message);
      auto pubkey_pem = EC::Point(X).to_public_pem();
      return check_signature(
        sig, {pubkey_pem.data(), pubkey_pem.data() + pubkey_pem.size()});
    }

    bool check_signature(
      const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pem) const
    {
      LOG_TRACE_FMT(
        "SPLITID: checking signature: {} with public key: {}",
        to_hex(sig),
        std::string(pem.begin(), pem.end()));

      auto h = hash(message);
      auto bio = BIO_new_mem_buf(pem.data(), pem.size());
      EC_KEY* pubkey = PEM_read_bio_EC_PUBKEY(bio, NULL, NULL, NULL);
      BIO_free(bio);

      int vr =
        ECDSA_verify(0, h.data(), h.size(), sig.data(), sig.size(), pubkey);

      if (vr == -1)
      {
        LOG_DEBUG_FMT(
          "SPLITID: OpenSSL error during signature verification: {}",
          ERR_get_error());
      }

      EC_KEY_free(pubkey);
      return vr == 1;
    }

    std::vector<uint8_t> mk_signature(
      const NID& nid,
      KeyPair& node_key,
      const std::map<NID, std::vector<uint8_t>>& public_keys,
      const BigNum& r_cached,
      std::vector<EC::CompressedPoint>& x_commits,
      Identity& identity) const
    {
      LOG_TRACE_FMT("SPLITID: {}: mk_signature x_commits: {}", nid, x_commits);

      if (signature_shares.size() < upper_threshold())
      {
        throw std::runtime_error(fmt::format(
          "invalid number of signature shares: {}, expected {}",
          signature_shares.size(),
          upper_threshold()));
      }

      const auto& go = EC::curve_parameters[curve].order;

      BigNum r = r_cached;
      if (r == BigNum::zero())
      {
        r = interpolate_x(encrypted_deals);
      }

      assert(r != BigNum::zero());

      std::vector<size_t> indices;
      std::vector<BigNum> ak_shares, s_shares;
      for (auto& [onid, sign] : signature_shares)
      {
        if (defensive)
        {
          std::vector<EC::CompressedPoint> batched_commits;
          auto commitments = get_deal_commitments(encrypted_deals);
          batch_commits(onid, commitments, batched_commits);
          check_signature_share(nid, onid, sign, r, x_commits, batched_commits);
        }

        indices.push_back(get_sharing_index(onid));
        ak_shares.push_back(sign.ak);
        s_shares.push_back(sign.s);
      }

      auto ak =
        BigNum::lagrange_interpolate(ak_shares, indices, BigNum::zero(), go);
      auto s_1 =
        BigNum::lagrange_interpolate(s_shares, indices, BigNum::zero(), go);
      auto s = s_1.mod_mul(ak.mod_inv(go), go);

      ECDSA_SIG* ecdsa_sig = ECDSA_SIG_new();
      BIGNUM *rd, *sd;
      CHECKNULL(rd = BN_dup(r.raw()));
      CHECKNULL(sd = BN_dup(s.raw()));
      CHECK1(ECDSA_SIG_set0(ecdsa_sig, rd, sd));

      std::vector<uint8_t> der_sig;
      der_sig.resize(i2d_ECDSA_SIG(ecdsa_sig, NULL));
      auto data = der_sig.data();
      i2d_ECDSA_SIG(ecdsa_sig, &data);
      ECDSA_SIG_free(ecdsa_sig);

      LOG_TRACE_FMT("SPLITID: {}: signature={}", nid, to_hex(der_sig));

      if (!check_signature(der_sig, identity.public_key))
      {
        throw std::runtime_error("signature validation failed");
      }
      else
      {
        LOG_TRACE_FMT("SPLITID: {}: signature validation passed", nid);
      }

      return der_sig;
    }

    void add_signature(const NID& from, const std::vector<uint8_t>& signature)
    {
      LOG_DEBUG_FMT("SPLITID: signature from {}", from);

      if (std::find(config.begin(), config.end(), from) == config.end())
        throw std::logic_error("Unsolicited signature");

      this->signature = signature;
    }
  };

  template <typename NID>
  struct NodeState
  {
    NodeState(const NID& nid, EC::CurveID curve = EC::CurveID::SECP384R1) :
      nid(nid),
      node_key(curve),
      next_deal_id(0)
    {
      x = BigNum::make_zero();
      x_witness = BigNum::make_zero();
    }

    NodeState(const NID& nid, EVP_PKEY* key) :
      nid(nid),
      node_key(key),
      next_deal_id(0)
    {
      x = BigNum::make_zero();
      x_witness = BigNum::make_zero();
    }

    NodeState(NodeState&&) = default;

    virtual ~NodeState() {}

    NID nid;
    KeyPair node_key;
    std::map<NID, std::vector<uint8_t>> public_keys;

    uint64_t
      next_deal_id; // unversioned; we cannot reuse deals after a rollback.
    std::map<NID, uint64_t> max_deal_ids_seen;

    BigNum x;
    BigNum x_witness;

    Identity identity;

    void clear()
    {
      x = BigNum::zero();
      x_witness = BigNum::zero();
      identity.public_key.clear();
      identity.x_commits.clear();
    }
  };

  template <typename NID>
  class RequestAdapter
  {
  public:
    RequestAdapter() {}
    virtual ~RequestAdapter() {}

    virtual bool submit_registration(
      const std::vector<uint8_t>& public_key) const = 0;

    virtual uint64_t sample(
      const std::vector<NID>& config,
      bool defensive,
      uint64_t app_id = 0) const = 0;

    virtual bool submit_sampling_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const = 0;
    virtual bool submit_sampling_resharing(
      uint64_t session_id,
      const EncryptedResharing& encrypted_resharing) const = 0;
    virtual bool submit_open_key(
      uint64_t session_id, const OpenKey& open_key) const = 0;
    virtual bool submit_identity(
      uint64_t session_id, const Identity& identity) const = 0;

    virtual uint64_t sign(
      const std::vector<NID>& config,
      const std::vector<uint8_t>& message,
      bool defensive,
      uint64_t app_id = 0) const = 0;

    virtual bool submit_signing_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const = 0;
    virtual bool submit_openk(
      uint64_t session_id, const OpenK& openk) const = 0;
    virtual bool submit_signature_share(
      uint64_t session_id, const SignatureShare& signature_share) const = 0;
    virtual bool submit_signature(
      uint64_t session_id, const std::vector<uint8_t>& signature) const = 0;

    virtual uint64_t reshare(
      const Identity& current_identity,
      const std::vector<NID>& config,
      const std::vector<NID>& next_config,
      bool defensive,
      uint64_t app_id = 0) const = 0;

    virtual bool submit_resharing_deal(
      uint64_t session_id, const EncryptedDeal& encrypted_deal) const = 0;
    virtual bool submit_resharing_resharing(
      uint64_t session_id,
      const EncryptedResharing& encrypted_reshare) const = 0;
    virtual bool submit_complete_resharing(uint64_t session_id) const = 0;
  };

  template <typename NID>
  class Context
  {
  public:
    Context(
      const NID& nid,
      std::shared_ptr<RequestAdapter<NID>> request_adapter,
      bool defensive = false) :
      nid(nid),
      defensive(defensive),
      request_adapter(request_adapter),
      state(nid)
    {}

    Context(
      const NID& nid,
      std::shared_ptr<RequestAdapter<NID>> request_adapter,
      EVP_PKEY* key,
      bool defensive = false) :
      nid(nid),
      defensive(defensive),
      request_adapter(request_adapter),
      state(nid, key)
    {}

    Context(Context&) = delete;

    virtual ~Context() {}

    virtual bool register_public_key() const
    {
      return request_adapter->submit_registration(
        state.node_key.public_key_pem);
    }

    const std::vector<uint8_t>& public_key() const
    {
      return state.node_key.public_key_pem;
    }

    bool have_public_key(const NID& nid)
    {
      return state.public_keys.find(nid) != state.public_keys.end();
    }

    virtual uint64_t sample(
      const std::vector<NID>& config, uint64_t app_id = 0) const
    {
      return request_adapter->sample(config, defensive, app_id);
    }

    virtual uint64_t sign(
      const std::vector<NID>& config,
      const std::vector<uint8_t>& message,
      uint64_t app_id = 0) const
    {
      return request_adapter->sign(config, message, defensive, app_id);
    }

    virtual uint64_t reshare(
      const std::vector<NID>& config,
      const std::vector<NID>& next_config,
      uint64_t app_id = 0) const
    {
      auto from = config;
      std::sort(from.begin(), from.end());
      auto to = next_config;
      std::sort(to.begin(), to.end());
      return request_adapter->reshare(
        state.identity, from, to, defensive, app_id);
    }

    typedef struct
    {
      typedef enum
      {
        SESSION_CREATED = 0,
        SUBMITTED_DEAL = 1,
        SUBMITTED_OPENK = 2,
        SUBMITTED_SIGNATURE_SHARE = 3,
        SUBMITTED_SIGNATURE = 4,
        COMPARED_SIGNATURE = 5
      } ProtocolState;

      ProtocolState protocol_state = SESSION_CREATED;
      BigNum r = BigNum::zero();
    } SigningSessionCache;

    typedef struct
    {
      typedef enum
      {
        SESSION_CREATED = 0,
        SUBMITTED_DEAL = 1,
        SUBMITTED_RESHARING = 2,
        COMMITMENTS_UPDATED = 3
      } ProtocolState;
      ProtocolState protocol_state = SESSION_CREATED;
    } ResharingSessionCache;

    typedef struct
    {
      typedef enum
      {
        SESSION_CREATED = 0,
        SUBMITTED_DEAL = 1,
        SUBMITTED_RESHARING = 2,
        SUBMITTED_OPEN_KEY = 3,
        COMPUTED_PUBLIC_KEY = 4
      } ProtocolState;
      ProtocolState protocol_state = SESSION_CREATED;
    } SamplingSessionCache;

    virtual std::optional<SigningSessionCache> get_local_signing_state(
      uint64_t id) const = 0;

    virtual void set_local_signing_state(
      uint64_t id, const std::optional<SigningSessionCache>& state) = 0;

    virtual std::optional<ResharingSessionCache> get_local_resharing_state(
      uint64_t id) const = 0;

    virtual void set_local_resharing_state(
      uint64_t id, const std::optional<ResharingSessionCache>& state) = 0;

    virtual std::optional<SamplingSessionCache> get_local_sampling_state(
      uint64_t id) const = 0;

    virtual void set_local_sampling_state(
      uint64_t id, const std::optional<SamplingSessionCache>& state) = 0;

    virtual bool on_public_key_update(
      const NID& nid, const std::vector<uint8_t>& public_key)
    {
      state.public_keys[nid] = public_key;
      return true;
    }

    virtual bool on_signing_update(uint64_t id, const SigningSession<NID>& s)
    {
      auto cache = get_local_signing_state(id);

      LOG_TRACE_FMT(
        "SPLITID: {}: Updating signing session #{}; deals={} openks={} "
        "signature_shares={} lower_threshold={} upper_threshold={} protocol "
        "state: {} config: {}",
        nid,
        id,
        s.encrypted_deals.size(),
        s.openks.size(),
        s.signature_shares.size(),
        s.lower_threshold(),
        s.upper_threshold(),
        cache.has_value() ? cache->protocol_state : -1,
        fmt::join(s.config, ", "));

#if defined(_DEBUG) && defined(NLOHMANN_JSON_VERSION_MAJOR) && \
  NLOHMANN_JSON_VERSION_MAJOR >= 3
      nlohmann::json j;
      to_json(j, s);
      LOG_DEBUG_FMT("SPLITID: session={}", j.dump());
#endif

      if (std::find(s.config.begin(), s.config.end(), nid) == s.config.end())
      {
        return false;
      }

      bool r = true;

      size_t openk_threshold =
        s.defensive ? s.lower_threshold() : s.upper_threshold();

      if (state.identity.public_key.empty())
      {
        throw std::runtime_error("no key to sign with yet");
      }

      if (
        (!cache.has_value() ||
         cache->protocol_state == SigningSessionCache::SESSION_CREATED) &&
        s.encrypted_deals.size() < s.lower_threshold())
      {
        if (
          s.encrypted_deals.find(s.get_node_index(nid)) ==
          s.encrypted_deals.end())
        {
          r = request_adapter->submit_signing_deal(
            id,
            s.mk_deal(
              nid, state.node_key, state.public_keys, state.next_deal_id++));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SigningSessionCache();
          cache->protocol_state = SigningSessionCache::SUBMITTED_DEAL;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < SigningSessionCache::SUBMITTED_OPENK) &&
        s.encrypted_deals.size() >= s.lower_threshold() &&
        s.openks.size() < openk_threshold)
      {
        if (s.openks.find(nid) == s.openks.end())
        {
          r = request_adapter->submit_openk(
            id,
            s.mk_openk(
              nid, state.node_key, state.public_keys, state.max_deal_ids_seen));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SigningSessionCache();
          cache->protocol_state = SigningSessionCache::SUBMITTED_OPENK;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state <
           SigningSessionCache::SUBMITTED_SIGNATURE_SHARE) &&
        s.openks.size() >= openk_threshold &&
        s.signature_shares.size() < s.upper_threshold())
      {
        if (s.signature_shares.find(nid) == s.signature_shares.end())
        {
          r = request_adapter->submit_signature_share(
            id,
            s.mk_signature_share(
              nid,
              state.x,
              state.x_witness,
              state.node_key,
              state.public_keys,
              cache->r));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SigningSessionCache();
          cache->protocol_state =
            SigningSessionCache::SUBMITTED_SIGNATURE_SHARE;
        }
      }
      else if (
        s.signature_shares.size() >= s.upper_threshold() &&
        (!cache.has_value() ||
         (cache->protocol_state != SigningSessionCache::SUBMITTED_SIGNATURE &&
          cache->protocol_state != SigningSessionCache::COMPARED_SIGNATURE)))
      {
        auto signature = s.mk_signature(
          nid,
          state.node_key,
          state.public_keys,
          cache->r,
          state.identity.x_commits,
          state.identity);

        if (s.signature.empty())
        {
          // The first node in the config writes the signature to the table.
          if (s.config.front() == nid)
          {
            r = request_adapter->submit_signature(id, signature);

            if (r)
            {
              if (!cache.has_value())
                cache = SigningSessionCache();
              cache->protocol_state = SigningSessionCache::SUBMITTED_SIGNATURE;
            }
          }
        }
        else
        {
          // Other nodes compare the signature
          if (signature != s.signature)
          {
            // disagreement -> blame
          }
          else
          {
            // OK, done, final state
            if (!cache.has_value())
              cache = SigningSessionCache();
            cache->protocol_state = SigningSessionCache::COMPARED_SIGNATURE;
            cache->r = BigNum::zero();
          }
        }
      }
      else
      {
        LOG_TRACE_FMT("SPLITID: Nothing to do!");
        r = false;
      }

      if (r && cache.has_value())
        set_local_signing_state(id, cache);

      return r;
    }

    virtual bool on_sampling_update(uint64_t id, const SamplingSession<NID>& s)
    {
      auto cache = get_local_sampling_state(id);

      LOG_TRACE_FMT(
        "SPLITID: {}: Updating sampling session #{}; deals={} reshares={} "
        "open_keys={} protocol_state={}",
        nid,
        id,
        s.encrypted_deals.size(),
        s.encrypted_reshares.size(),
        s.open_keys.size(),
        cache.has_value() ? cache->protocol_state : -1);

#if defined(_DEBUG) && defined(NLOHMANN_JSON_VERSION_MAJOR) && \
  NLOHMANN_JSON_VERSION_MAJOR >= 3
      nlohmann::json j;
      to_json(j, s);
      LOG_DEBUG_FMT("SPLITID: session={}", j.dump());
#endif

      if (
        std::find(s.config.begin(), s.config.end(), nid) == s.config.end() &&
        std::find(s.next_config.begin(), s.next_config.end(), nid) ==
          s.next_config.end())
        return true;

      bool r = true;

      if (
        (!cache.has_value() ||
         cache->protocol_state == SamplingSessionCache::SESSION_CREATED) &&
        s.encrypted_deals.size() < s.lower_threshold())
      {
        if (
          s.encrypted_deals.find(s.get_node_index(nid)) ==
          s.encrypted_deals.end())
        {
          r = request_adapter->submit_sampling_deal(
            id,
            s.mk_deal(
              nid, state.node_key, state.public_keys, state.next_deal_id++));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SamplingSessionCache();
          cache->protocol_state = SamplingSessionCache::SUBMITTED_DEAL;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < SamplingSessionCache::SUBMITTED_RESHARING) &&
        s.encrypted_deals.size() >= s.lower_threshold() &&
        s.encrypted_reshares.size() < s.upper_threshold())
      {
        if (
          s.encrypted_reshares.find(s.get_node_index(nid)) ==
          s.encrypted_reshares.end())
        {
          r = request_adapter->submit_sampling_resharing(
            id,
            s.mk_resharing(
              nid,
              state.x,
              state.x_witness,
              state.node_key,
              state.public_keys,
              state.max_deal_ids_seen));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SamplingSessionCache();
          cache->protocol_state = SamplingSessionCache::SUBMITTED_RESHARING;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < SamplingSessionCache::SUBMITTED_OPEN_KEY) &&
        s.encrypted_reshares.size() >= s.upper_threshold() &&
        s.open_keys.size() < s.lower_threshold())
      {
        if (s.open_keys.find(s.get_node_index(nid)) == s.open_keys.end())
        {
          r = request_adapter->submit_open_key(
            id,
            s.mk_open_key(
              nid,
              state.x,
              state.x_witness,
              state.node_key,
              state.public_keys,
              state.identity.x_commits));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = SamplingSessionCache();
          cache->protocol_state = SamplingSessionCache::SUBMITTED_OPEN_KEY;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < SamplingSessionCache::COMPUTED_PUBLIC_KEY) &&
        s.open_keys.size() >= s.lower_threshold() &&
        s.encrypted_reshares.size() >= s.upper_threshold() &&
        (state.x == BigNum::zero() || state.x_witness == BigNum::zero()))
      {
        // Nodes that don't have resharings in the session still need to
        // interpolate their private key shares and commitments.
        LOG_TRACE_FMT("SPLITID: {}: computing private shares", nid);
        s.compute_private_shares(
          nid,
          state.node_key,
          state.public_keys,
          state.x,
          state.x_witness,
          state.identity.x_commits);
      }
      else if (
        s.open_keys.size() >= s.lower_threshold() &&
        state.identity.public_key.empty())
      {
        s.compute_public_key(
          nid, state.identity.x_commits, state.identity.public_key);

        if (s.config.front() == nid)
        {
          // The first node in the config writes the public key to the current
          // identity table?
          if (!request_adapter->submit_identity(id, state.identity))
          {
            throw std::runtime_error("sampling identity submission failed");
          }
        }

        if (!cache.has_value())
          cache = SamplingSessionCache();
        cache->protocol_state = SamplingSessionCache::COMPUTED_PUBLIC_KEY;
      }
      else
      {
        LOG_TRACE_FMT("SPLITID: Nothing to do!");
        r = false;
      }

      if (r && cache.has_value())
        set_local_sampling_state(id, cache);

      return r;
    }

    virtual bool on_resharing_update(
      uint64_t id, const ResharingSession<NID>& s)
    {
      auto cache = get_local_resharing_state(id);

      LOG_DEBUG_FMT(
        "SPLITID: {}: Updating resharing session #{}; deals={} reshares={} "
        "protocol_state={} x_commits={}",
        nid,
        id,
        s.encrypted_deals.size(),
        s.encrypted_reshares.size(),
        cache.has_value() ? cache->protocol_state : -1,
        state.identity.x_commits);

#if defined(_DEBUG) && defined(NLOHMANN_JSON_VERSION_MAJOR) && \
  NLOHMANN_JSON_VERSION_MAJOR >= 3
      nlohmann::json j;
      to_json(j, s);
      LOG_DEBUG_FMT("SPLITID: session={}", j.dump());
#endif

      if (
        std::find(s.config.begin(), s.config.end(), nid) == s.config.end() &&
        std::find(s.next_config.begin(), s.next_config.end(), nid) ==
          s.next_config.end())
        return true;

      bool r = true;

      if (
        (!cache.has_value() ||
         cache->protocol_state == ResharingSessionCache::SESSION_CREATED) &&
        s.encrypted_deals.size() < s.lower_threshold() &&
        std::find(s.config.begin(), s.config.end(), nid) != s.config.end())
      {
        if (
          s.encrypted_deals.find(s.get_node_index(nid)) ==
          s.encrypted_deals.end())
        {
          r = request_adapter->submit_resharing_deal(
            id,
            s.mk_deal(
              nid, state.node_key, state.public_keys, state.next_deal_id++));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = ResharingSessionCache();
          cache->protocol_state = ResharingSessionCache::SUBMITTED_DEAL;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < ResharingSessionCache::SUBMITTED_RESHARING) &&
        s.encrypted_deals.size() >= s.lower_threshold() &&
        s.encrypted_reshares.size() < s.upper_threshold())
      {
        if (std::find(s.config.begin(), s.config.end(), nid) == s.config.end())
        {
          r = false; // new nodes do not reshare
        }
        else if (
          s.encrypted_reshares.find(s.get_node_index(nid, false)) ==
          s.encrypted_reshares.end())
        {
          r = request_adapter->submit_resharing_resharing(
            id,
            s.mk_resharing(
              nid,
              state.x,
              state.x_witness,
              state.node_key,
              state.public_keys,
              state.max_deal_ids_seen));
        }

        if (r)
        {
          if (!cache.has_value())
            cache = ResharingSessionCache();
          cache->protocol_state = ResharingSessionCache::SUBMITTED_RESHARING;
        }
      }
      else if (
        (!cache.has_value() ||
         cache->protocol_state < ResharingSessionCache::COMMITMENTS_UPDATED) &&
        s.encrypted_reshares.size() >= s.upper_threshold())
      {
        if (
          std::find(s.next_config.begin(), s.next_config.end(), nid) ==
          s.next_config.end())
        {
          // Retiring nodes clear their state.
          LOG_DEBUG_FMT("SPLITID: {}: clearing state", nid);
          state.clear();
        }
        else
        {
          // The other nodes update their commitments.
          s.update_commitments(
            state.nid,
            state.node_key,
            state.public_keys,
            state.x,
            state.x_witness,
            state.identity);
        }

        // The first node in the config saves the result.
        if (s.config.front() == nid)
        {
          r = request_adapter->submit_complete_resharing(id);
        }

        if (r)
        {
          if (!cache.has_value())
            cache = ResharingSessionCache();
          cache->protocol_state = ResharingSessionCache::COMMITMENTS_UPDATED;
        }
      }
      else
      {
        LOG_TRACE_FMT("SPLITID: Nothing to do!");
        r = false;
      }

      if (r && cache.has_value())
        set_local_resharing_state(id, cache);

      return r;
    }

    virtual void on_rollback() {}
    virtual void on_compact() {}

  public:
    NID nid;
    bool defensive;
    std::shared_ptr<RequestAdapter<NID>> request_adapter;
    NodeState<NID> state;
  };
}
