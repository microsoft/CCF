// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "crypto/curve.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <string>
#include <vector>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

using namespace crypto;

namespace ByzIdent
{
  class Polynomial
  {
  public:
    Polynomial(const Polynomial&) = delete;

    Polynomial(
      CurveID curve,
      size_t t,
      const std::vector<std::string>& coefficient_strings = {})
    {
      ctx = BN_CTX_new();

      switch (curve)
      {
        case CurveID::SECP384R1:
          group = EC_GROUP_new_by_curve_name(NID_secp384r1);
          break;
        case CurveID::SECP256R1:
          group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
          break;
        default:
          throw std::logic_error("unsupported curve");
      }

      group_order = BN_new();
      EC_GROUP_get_order(group, group_order, ctx);

      if (coefficient_strings.size() > 0)
      {
        for (size_t i = 0; i < coefficient_strings.size(); i++)
        {
          coefficients.push_back(BN_new());
          BN_dec2bn(&coefficients[i], coefficient_strings[i].c_str());
        }
      }
      else
      {
        for (size_t i = 0; i < t + 1; i++)
        {
          BIGNUM* x = BN_new();
          BN_rand_range(x, group_order);
          coefficients.push_back(x);
        }
      }
    }

    virtual ~Polynomial()
    {
      for (auto c : coefficients)
      {
        BN_free(c);
      }
      BN_free(group_order);
      EC_GROUP_free(group);
      BN_CTX_free(ctx);
    }

    BIGNUM* eval(BIGNUM* input) const
    {
      BIGNUM* result = BN_new();
      BIGNUM *t1 = BN_new(), *t2 = BN_new();
      for (size_t i = 0; i < coefficients.size(); i++)
      {
        BIGNUM* t0 = BN_new();
        BN_set_word(t0, i);
        BN_mod_exp(t1, input, t0, group_order, ctx);
        BN_mod_mul(t2, coefficients[i], t1, group_order, ctx);
        BN_mod_add(result, result, t2, group_order, ctx);
        BN_free(t0);
      }
      BN_free(t2);
      BN_free(t1);
      return result;
    }

    static Polynomial* sample_rss(
      CurveID curve, size_t t, size_t num_coefficients = 0)
    {
      Polynomial* r = new Polynomial(curve, t);

      if (num_coefficients > t)
      {
        // really num_coefficients+1 or just num_coefficients?
        for (size_t i = t + 1; i < num_coefficients + 1; i++)
        {
          BIGNUM* zero = BN_new();
          BN_zero(zero);
          r->coefficients.push_back(zero);
        }
      }

      return r;
    }

    static Polynomial* sample_zss(
      CurveID curve, size_t t, BIGNUM* coeff0 = nullptr)
    {
      assert(t > 0);
      Polynomial* r = new Polynomial(curve, t - 1);
      if (!coeff0)
      {
        coeff0 = BN_new();
        BN_zero(coeff0);
      }
      r->coefficients.insert(r->coefficients.begin(), coeff0);
      return r;
    }

    std::vector<BIGNUM*> coefficients;

    std::string to_string()
    {
      std::stringstream r;
      r << "[";
      bool first = true;
      for (const auto& c : coefficients)
      {
        if (first)
        {
          first = false;
        }
        else
        {
          r << ", ";
        }
        char* cs = BN_bn2dec(c);
        r << cs;
        OPENSSL_free(cs);
      }
      r << "]";
      return r.str();
    }

  protected:
    BN_CTX* ctx;
    EC_GROUP* group;
    BIGNUM* group_order;
  };

  struct Share : std::vector<BIGNUM*> {};

  class Deal
  {
  public:
    Deal(const std::vector<Polynomial*>& sharings = {}) : sharings(sharings) {}
    virtual ~Deal() {}

  protected:
    std::vector<Polynomial*> sharings;
  };

  class SigningDeal : public Deal
  {
  public:
    SigningDeal(
      size_t t,
      const std::vector<size_t>& indices,
      bool defensive = false,
      CurveID curve = CurveID::SECP384R1) :
      Deal(), curve(curve), t(t), indices_(indices)
    {
      sample(t, defensive);
      compute_shares();

      if (defensive)
      {
        // commits = [ compress(commit.multi(2, deal.coefficients(u))) for u in
        // range(2*t+1) ] c0 = deal.coefficients(0) non_zero_shares = c0[0:2] +
        // [ c0[4] ] proof = zkp.prove_zeroes(commits[0], non_zero_shares),
        // zkp.prove_456(commits[t+1:2*t+1], deal.higher_coefficients(t))
      }
    }

    virtual ~SigningDeal()
    {
      for (auto p : sharings)
      {
        delete p;
      }
      delete_shares();
    }

    void load(const std::vector<std::vector<std::string>>& ss)
    {
      for (auto p : sharings)
      {
        delete p;
      }
      sharings.clear();
      for (const std::vector<std::string>& s : ss)
      {
        sharings.push_back(new Polynomial(curve, t, s));
      }
      compute_shares();
    }

    const Polynomial* k() const
    {
      return sharings[0];
    }
    const Polynomial* a() const
    {
      return sharings[1];
    }
    const Polynomial* z() const
    {
      return sharings[2];
    }
    const Polynomial* y() const
    {
      return sharings[3];
    }
    const Polynomial* w() const
    {
      return sharings[4];
    }

    std::vector<Share> shares()
    {
      return shares_;
    }
    std::vector<uint8_t> commits()
    {
      return commits_;
    }
    std::vector<uint8_t> proof()
    {
      return proof_;
    }

    std::string to_string() const
    {
      std::stringstream r;
      r << "sharings={";
      bool first = true;
      for (const auto& s : sharings)
      {
        if (first)
          first = false;
        else
          r << ", ";
        r << s->to_string() << std::endl;
      }
      r << "}";
      r << std::endl;
      r << "shares={";
      first = true;
      for (const auto& s : shares_)
      {
        if (first)
          first = false;
        else
          r << ", ";
        BIGNUM* tmp = BN_new();
        for (const auto& p : s)
        {
          char *ps = BN_bn2dec(p);
          r << ps;
          OPENSSL_free(ps);
        }
        BN_free(tmp);
      }
      r << "}";
      return r.str();
    }

  protected:
    CurveID curve;
    size_t t;
    std::vector<size_t> indices_;
    std::vector<Share> shares_;
    std::vector<uint8_t> commits_, proof_;

    void sample(int64_t t, bool defensive = false)
    {
      sharings.push_back(Polynomial::sample_rss(curve, t, 2 * t));
      sharings.push_back(Polynomial::sample_rss(curve, t, 2 * t));
      sharings.push_back(Polynomial::sample_zss(curve, 2 * t));
      sharings.push_back(Polynomial::sample_zss(curve, 2 * t));
      sharings.push_back(
        defensive ? Polynomial::sample_rss(curve, 2 * t) : nullptr);
    }

    void delete_shares()
    {
      for (auto& share : shares_)
      {
        for (BIGNUM *bn : share)
        {
          BN_free(bn);
        }
      }
      shares_.clear();
    }

    void compute_shares()
    {
      delete_shares();
      for (auto index : indices_)
      {
        BIGNUM* input = BN_new();
        BN_set_word(input, index);
        shares_.resize(shares_.size()+1);
        for (auto s : sharings)
        {
          shares_.back().push_back(s->eval(input));
        }
        BN_free(input);
      }
    }
  };

}

using namespace ByzIdent;

TEST_CASE("Debug signing deal")
{
  size_t t = 2;
  std::vector<size_t> indices = {2, 5, 7};
  SigningDeal deal(t, indices, true);

  // clang-format off
  deal.load({
    { "10014884927522895850327356177777625667978260337939389002110941575532553449296052180537322023555523813228576607014520",
      "16341302935712828055939570400053371625442944138326862601309546139321868278170469229016276949582840172941386133934238",
      "22733325687411215076796313729157744702163634859070151867248808792760888847980819625421343878626948678252216382474849",
      "0",
      "0"},
      {"11971040240021253050855990733199357635264196602076534095139749962191011218714097886800203842464169762930539838981047",
      "30266522339766330547875209837816374563136257208888330801420119685406168349405731716334307208652403104319846043578207",
      "12833249415650484131911965264874336946692530010710652062211180234551822035172024552641821338390106873090080256466796",
      "0",
      "0"},
      {"0",
      "13205794569199814472461093117211428820752412125765014907879295308183638919356155487359875604880043216475786674000347",
      "34685344325380327964522083139003084435536306270999210711520074143743902170655670161491578907007091186639185307431684",
      "37639340622829321449596249844298857577682454924769540346973809852196699371678357930162248040236232354807684319526556",
      "6644660354369846524921448351859610398683307692243094993327170051671951633341461233013940975251333834595136764613802"},
      {"0",
      "30134393016483678268202705920662787806702929734540798373077032206049520195946227699361337750381791453786194458434954",
      "12847305610441416543274060940241723347866315369337480715735914830432962510600885905904575194059939024246355508660685",
      "39230436614667971035442643960925254786422087350648162248200488457081460325107010130294392673080943010276921843742880",
      "13370229149470308411214868724733664915736295307991931318216659880585842740848512916194692080062648886982658994040987"},
      {"37224616507411555438010701434640303823301245501366136207464259578561594034994592609033007855712496695382479867095728",
      "19607885985106249555562436727104543113555475738870997075409383775047480625454757535395098560141892903494018293441562",
      "17932138509996119236010145888837752011369384395140876275723775364518873491524504241197898792017477605547227198389377",
      "32207904579103540016219868188033273552381026460328589666178735109463097167278377132610280560603020370937575938331145",
      "14575218702365232574685903037462414017020863264884773918261013636785026093261895872237206718006461150584426313012233"}
    });

  std::vector<std::vector<const char*>> expected_shares = {
    { "15424774959409974632554631594084506312279470239477381669884553186336867200220478432058382512772114131456913442954463",
      "5631063992972413037417151167898613133067613251299463942983994432327657860873868821839234688872518723267251990176716",
      "20954170342950347826617129772569229112926262023056461979607412920880476040639544818621718449567522581729906212563708",
      "8993068641290058176016065283135325066752716352040571999017705005813506502916069613427890012216546661624791143029192",
      "8603579245968905421444910945567389905995930153009588795633743176954693696607258550909051186557015684539915299298960"},
    {"29622442649055745653468409804690280468008024178880352002728407617121565653856671850769002806706723017369978375474647",
      "11310812973381258540682690342416288457301861668699129642156990897485491055684207451729797647651318149128572621230266",
      "19295343609495686105592049675131727719768551576501482877773334606413410181291178167141800839421048159780037702464121",
      "20154244250614175489382546333576839200368753110142924223733476981980446522034402902065907540682233606924050180129006",
      "7169114203779879449143499359297170193231816046324995217557936929873817757447325889658444049276036917053777646036949"},
    {"16874772072433375424273478602428689494625060016236022000115331727611743575038327777929465170634747937989439013599854",
      "25223787860975225891808915473740600058477442909342420726543408380892622006604888023211517412948035089940287978105997",
      "1384957605588707963627717129332315118212548008822339547498466018241422426027059844341847314502562477260297450126001",
      "22257379580037686129144416330342364539137835662438161680059452077356003923739768576714345163541869281354807539145059",
      "10168575713000123602259968848472340438785757710205718293243014176955755855823983470602512563918937778902648570761918"}
    };
  // clang-format on

  const auto &ss = deal.shares();
  REQUIRE(ss.size() == expected_shares.size());
  for (size_t i=0; i < ss.size(); i++) {
    for (size_t j=0; j < ss[i].size(); j++) {
      char *val = BN_bn2dec(ss[i][j]);
      REQUIRE(strcmp(val, expected_shares[i][j]) == 0);
      OPENSSL_free(val);
    }
  }
}

TEST_CASE("Establish Byzantine identity of 3-node network")
{
  size_t t = 2;
  bool defensive = true;
  std::vector<size_t> indices = {2, 5, 7};
  SigningDeal deal(t, indices, defensive);
}
