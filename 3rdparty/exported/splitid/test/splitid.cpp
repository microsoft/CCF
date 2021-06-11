// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

// #include "crypto/verifier.h"
// #include "kv/kv_types.h"
// #include "node/splitid_context.h"

#include <algorithm>
#include <functional>
#include <memory>
#include <splitid/splitid.h>

#define FMT_HEADER_ONLY
#include <fmt/format.h>

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

using namespace SplitIdentity;

typedef std::string NodeId;

TEST_CASE("Polynomial evaluation example")
{
  // clang-format off
  std::vector<std::string> coefficients = {
    "7699140509354506296904379330388787711502937593685033925998668810583690207038429705926129602688681305405619847328173",
    "37918317783077992207075945298372013800209636724718746327158474975386339016607917448894651816099517951289611406292763",
    "3467828061652936489519861143038340128148454963564475447775042344042319260200137528770943678279745723710076733520812",
    "31550273572625802709384678740048388958405550483513682048313826168007327042521475275645189870165740186364950149570638",
    "307921627128950609390184175930712982756136233071715435787024235473522031567428100383716155375590382571736929796244",
    "17987233556361005764037359423216891628740372931380388256121900404198528245576272396610650932710031118771494292736282",
    "8022626363856810181081050720512516194870554147810831053444882051835195424353917408827605490318540556836533144678145",
    "1143739633003107074184532257423604655434275223885737188621261362924034487607223850341908606225434629784249592873081",
    "28336164975849996632750921038009054550241619710358810847675781408942232050965690324716480011465243344045015395410382",
    "23668433768395548708220181876672863765511850637728760044883254584889287121394895275659735818087588478357936296748282",
    "115432390781244234094084799873273367200321830214264663367137873187057456953982446441387228257870379944890950991721"
  };

  std::map<size_t, std::string> results = {
    {1, "2609087456509984057527018402911992522702753398070658567359633100958894748334315484622573977064804402864380124175951"},
    {2, "600033377045403364484255920750414802244459225451071411994749650517908153806670023114586889834379072236082298405102"},
    {3, "29310319541045889029523499721117601466204953540776880280292465147266293137454599033004832179027471011459591309275866"},
    {4, "30674060811933428438134790257833741728590304563906502401877617868711566605534431951105817440783678234574689043234246"},
    {5, "8596054703407938703354146902602246416276384934442656761502061183677529431032978595080841109993426528870644015417057"},
    {6, "23284152075511080359120803822706382404499440777170148704478424906646283059390062259087100518775917350097560808899835"},
    {7, "38801938255697858165670253411933197362309834593259297093307448622358228394171235389239638597556755701376284889136796"},
    {8, "15739837012746047375101252353593659466642327816633496998490110153155566115087314435231835120086659333295286399322916"},
    {9, "5317115941907074178522217571281491910407863541621567170807164058784430949367798316640619535895400048871974226517152"}
  };
  // clang-format on

  Polynomial p(coefficients);
  for (const auto& [i, r] : results)
  {
    BigNum index(i);
    auto expected = BigNum(r);
    auto evaluated =
      p.eval(index, EC::curve_parameters[EC::CurveID::SECP384R1].order);
    REQUIRE(evaluated == expected);
  }
}

TEST_CASE("eval_in_exp example")
{
  // clang-format off
  Polynomial x({"4662274122108106240021631361590296658730126368330097059057694451332620977124940553541538766554878574275001669017484",
                "33675137677133611122865516303654450565993338292559167149019978517657614407894919893430320610995988435933624324640604",
                "29938693961268115205839860967191776226677788049480965924904378120911331831629484753744027979147661882987167471837816",
                "2814179160133403102122249792568787642812274134710020886404395107248539719778229217090686697482047301813888071918032",
                "28706581893256681155333029483883573302643571770750349119682951144131078854169024628675431065019998414403591068704393",
                "29013080213192948770630283317606899082750338821925638807650004883930881714162572847338691579067731625526949307141709",
                "22277835779424603002613919326686976262180950474302526955819257779340759500944339529304205172014704263494460511780193",
                "35440436385253054038384837465415412797918228455748500485696920730421415029767073209870222232037432008215167236071971",
                "32626454062876124900292659304580646840391545751395301843192893654159795317431409074167024764187955718544963619697742",
                "15951010556255911853262159331589934991983724496395207028513345882793323509657590398839601819876612646214299884062578",
                "4002953525323384541588956777671823534581268689134507306918130036091859434380284294464962809268940152694276541514027"});
  Polynomial w({"29117916611984508997101164697719348480872803229200844293460579741596268798658425935628220465545115284255640760026118",
                "22058296101719147339117603351741704236645571069056617541995942737680700096777754912356128353628874214631316252203598",
                "21550564430006787468410098904226333903897534790440183736541830598160911637406692012720681466498301411701606054618274",
                "30565451733807820301835127004864770457865502575603872460487358628503302038277266268189640732395715811686374347823031",
                "924730760471921094888913951428273370497745348059205727495523761489746425388732529408804018716513758780010048460875",
                "36760932824321461192033670019132778307440191446272218814222493425237240235761675390675873086453592479488619428600408",
                "4870902973292053905752045330725667723058738673455228445994655206831609688539299207439989706543738485567986953402737",
                "23220699946359513675911173542337673765644240927366459702333870847069458047584522798385944230378558087346345987644290",
                "28531960007392007036008090557107942569764031460878473175417470145679155230511174651802411524226534155182096250282416",
                "9007345059127260787676892169584046250406266049565591678448486511438928164434208454507959619464989542719377447849882",
                "3433952102532624922890722998052513142964649357788507953803716788469362577587981131217762548959377364922610361795160"});  

  std::map<size_t, std::string> results = {
    {1, "0210b10513b12d4dca91be44c2511c8b93d4a020809f90fa665bb416c8c5a2cb5efce9c400532c964def5b5cba41af4ece"},
    {2, "0298066cd8b52a4501d7800e2109217f8c9ed4b7524b75ee0000aaeaa0e216541155cdc32a023a13017d0f6a47680f95c2"},
    {3, "02983c5dfdf10bc2e133f7e0fead745f2e5e8219f1bbb9458091e1c13ba090367c0feb7d771e3c29569f64135b036da9e3"},
    {4, "027ea4a6562e09ff2ca4cc8afb550b7714036f0687b1f434d59f7849cb99d1e276129b4273a792c6392968ff0d6ea99d7f"},
    {5, "02d625728341b049d127089adad073cef8983e910de0931983d33cf430953ff25f852d31965fdaed059e3f1f89ebde39be"},
    {6, "038bad4b72a189197f7c3dcb9ed6a7484d0323d4391b838422b3a7cddfc32d9ff0492773721615b9d2abb9f3e17e578f01"},
    {7, "036df27b7c47e0eda424530a55745501a434d04ccab7d0055d74d323cc7a23a7f7a994c51d95592f59c361a28b54a5cc56"},
    {8, "022639a21d01200a7f92cdb06bcc626cbcdd333cd4c81f666a2134f4328577820820b9f50147b7c22259bee943c10e6954"},
    {9, "0339defc1991b06e5bb2eaeeaaffd138f02defb017c4011a854d13b1531ea5bb32e1bc54e336b966413a1097ece2c1e94c"},
  };
  // clang-format on

  auto go = EC::group_order();

  std::vector<EC::CompressedPoint> commitments;
  for (size_t j = 0; j < x.coefficients.size(); j++)
  {
    auto c = compress_x_wx(x.coefficients[j], w.coefficients[j]);
    commitments.push_back(c);
  }

  std::vector<std::vector<BigNum>> shares;
  for (size_t i = 0; i < 10; i++)
  {
    shares.resize(shares.size() + 1);
    auto index = BigNum(i + 1); // <---- +1 sharing index
    shares.back().push_back(x.eval(index, go));
    shares.back().push_back(w.eval(index, go));
  }

  for (size_t i = 1; i < 10; i++) // <---- +1 sharing index
  {
    auto eval_i = EC::eval_in_exp(commitments, i, go).compress();
    auto expected_i = compress_x_wx(shares[i - 1][0], shares[i - 1][1]);
    REQUIRE(eval_i == expected_i);
  }
}

TEST_CASE("eval_in_exp")
{
  size_t degree = 10;
  auto go = EC::group_order();

  auto x = Polynomial::sample_rss(degree);
  auto w = Polynomial::sample_rss(degree);

  std::vector<EC::CompressedPoint> commitments;
  for (size_t j = 0; j < degree + 1; j++)
  {
    auto c = compress_x_wx(x->coefficients[j], w->coefficients[j]);
    commitments.push_back(c);
  }

  std::vector<std::vector<BigNum>> shares;
  for (size_t i = 0; i < 10; i++)
  {
    shares.resize(shares.size() + 1);
    auto index = BigNum(i + 1); // <---- +1 sharing index
    shares.back().push_back(x->eval(index, go));
    shares.back().push_back(w->eval(index, go));
  }

  for (size_t i = 1; i < 10; i++) // <---- +1 sharing index
  {
    auto eval_i = EC::eval_in_exp(commitments, i, go).compress();
    auto expected_i = compress_x_wx(shares[i - 1][0], shares[i - 1][1]);
    REQUIRE(eval_i == expected_i);
  }
}

TEST_CASE("Point compression example")
{
  // clang-format off
  auto x = BigNum("44743853537480180443520925379132040042002684141002748352811143751284261915166039290693308915657510350410983457679936");
  auto wx = BigNum("14683125135257787570162326319919597336533164736109972311473321227447104754776945196531521943653178855539464455193453");
  std::string result = "035a76d78d03d8efb5d356803ff18c4df30e79ce81f9f5d127a367c3dfa65c632ac9f75a60f0195b07282b9864a17a80bd";
  // clang-format on

  auto computed = to_hex(compress_x_wx(x, wx));
  REQUIRE(computed == result);
}

TEST_CASE("Coefficient sum example")
{
  // clang-format off
  std::vector<SharePolynomials> sp = {
    {
      Polynomial({BigNum("5915022295699250484540554978180773988888296736599271417160786959649247307294099764185470405428602363247658116227438"), BigNum("29830293207082016981012389058417221261502225534799763539880716818983507516779862868134315836023930517210394645335567")}),
      Polynomial({BigNum("6641347515181446222822120506332362725077971803701127709120517968263585908094858075855642247067094778450235763135400"), BigNum("10366137176930826149881472566228629804995666946536158496205649181100006527574439571823822501712926260589215081486404")})
    },
    {
      Polynomial({BigNum("12765128487249872987578856086560716832733736790696063183173521838900712311250556378645680572216399440053730177395610"), BigNum("16586850211669718366973542591259551202378486259002068521905326504916339718281336197199721300472727946525064979454866")}),
      Polynomial({BigNum("13937892153500515522265860880945360620435140277146765408239312989720441470566521807349416775367219902914189299022306"), BigNum("20657630538132061634237733051870863162488151076418947277342092056147758046347224647554545022786418204528179968984929")})
    }
  };

  std::vector<std::vector<BigNum>> expected = {
    { BigNum("18680150782949123472119411064741490821622033527295334600334308798549959618544656142831150977645001803301388293623048"), BigNum("7015137222357256135706891549533158658800972523336385393839138044272187835947935495935080828344363550181025970847790") },
    { BigNum("20579239668681961745087981387277723345513112080847893117359830957984027378661379883205059022434314681364425062157706"), BigNum("31023767715062887784119205618099492967483818022955105773547741237247764573921664219378367524499344465117395050471333") },
  };
  // clang-format on

  auto go = EC::group_order();
  auto sum = sum_share_polys(sp, go);
  REQUIRE(sum.size() == expected.size());
  for (size_t i = 0; i < sum.size(); i++)
  {
    REQUIRE(sum[i].size() == expected[i].size());
    for (size_t j = 0; j < sum[i].size(); j++)
    {
      REQUIRE(sum[i][j] == expected[i][j]);
    }
  }
}

TEST_CASE("Transfer share verification example")
{
  // clang-format off
  size_t j = 2, k = 1;
  auto x_jk = BigNum("3404745399376387349446961464068304116895309782550445238162763701247255203701755839194006564838437870466872039811625");
  auto wx_jk = BigNum("1182408208388050279587480277067963893298271305571199070749252435618088813722947198735605835372380041003730880430432");

  std::vector<std::vector<EC::CompressedPoint>> q_commits = {
      { from_hex("038d3dcaf7a137fee6a76117d8fc48b907502f0ec349baa5be0d327bf1aa5223f2c036d4740b0e803f6a403ba82f33248b"), from_hex("031ad5bef2a548fda7c13e79e259e8e3e0227358557ddcc05e5f78847237cdb1d73f48e7095e0ee5f4641b653347b50fdc") },
      { from_hex("02bd86407b1d5af797a08e9eefbf3e0d2527844a256e3da73e5cafb7b9827ee6c266ca9ba2cdbd2947be24ebb5d1c279cc"), from_hex("023e60f748d0e502f92e6f48d88246968676e772bccf3276ede5849fabc0023a8d38182ebc0fc8fc0791ed064e6246f6f5")}
  };

  std::vector<EC::CompressedPoint> qj_commits = { from_hex("03373dda8f03ff0970136bbbc0d991c7f98154541cb0c92c4bf433254566fa43b97b4e9e7f32cb6e4fd9b8e2d0c944be73"), from_hex("032c989877e9ab0d861bbbbf9cce7566be451d2fdcbc87753a5fc85e5c7e0c68fe336407b198bc1d595903fd255984bc13") };


  EC::CompressedPoint expected = from_hex("03bdc297bd2191eca8da2db5f2669634d4b98bb6e049ca800c3f67ef37301fb5f1af44d3c56dd611c7208e5e94e8cd9009");
  // clang-format on

  size_t t = 1;
  std::vector<NodeId> nids;
  for (size_t i = 0; i < 3 * t + 1; i++)
  {
    nids.push_back(NodeId(std::to_string(i)));
  }

  SamplingSession s(nids, false);

  std::vector<EC::CompressedPoint> x_commits = {from_hex("00")};
  REQUIRE_NOTHROW(s.verify_transfer_shares(
    q_commits, x_commits, nids[k - 1], nids[j - 1], x_jk, wx_jk));
}

TEST_CASE("Transfer share verification example 2")
{
  // clang-format off
  size_t j = 3, k = 2;
  auto x_jk = BigNum("12062364093736520888717105107218074030973304316729793466779616817057436355915221370697778439765679835758839732852148");
  auto wx_jk = BigNum("27906723981776944258487792706296304860283159050826708389424578642098345842214816843589571192377365370104711161526696");

  std::vector<std::vector<EC::CompressedPoint>> q_commits = {
      { from_hex("034795a0fe55dfaa79f4bb53149b3e57157e6bc8c41f4a010fbb0940925cb8678fa1081fa1d9058f476d95c50e658501aa"), from_hex("03ccc418f7bccb4fa1ea47799625e4cfc9b9df3207417a7f1b3f90d3c5b860ac25ec3aa53c29b74580c46d22a768f099dc") },
      { from_hex("02b1ae3953ade8258913e4b99bac7a5355a1eb45ccd3b6357562023fbf90673d22c27b8e0ce5feb7a12831d0bca919587f"), from_hex("02c518ea16cd46fb87397f0ed9a5fdafb5b6d001ba7d531b67db0c00ba21dee268b81b87d5f9dbece773f3cd2dd6971adc")}
  };

  std::vector<EC::CompressedPoint> qj_commits = { from_hex("02b2e32137cc64ae2be3ba2f82ead3eaab22dce3c8ed58185ddf5ae06a53fe87b0e2d1f3b9f67f4c6d6a60b6141217c07a"), from_hex("039f464ec777e391231f7d54f5490c9b2f62b49a9e3946a870a462aa7b6190fc5974f07eaf1384272b1958457c47cbe057") };

  EC::CompressedPoint expected = from_hex("0255e5727fdb0a44bb855977a4ecec6ab835ca098efe28e982ffde837e4656b5392c1b5288255937ef3411a67d4a0236a3");
  // clang-format on

  size_t t = 1;
  std::vector<NodeId> nids;
  for (size_t i = 0; i < 3 * t + 1; i++)
  {
    nids.push_back(NodeId(std::to_string(i)));
  }
  SamplingSession s(nids, false);

  std::vector<EC::CompressedPoint> x_commits = {from_hex("00")};
  REQUIRE_NOTHROW(s.verify_transfer_shares(
    q_commits, x_commits, nids[k - 1], nids[j - 1], x_jk, wx_jk));
}

TEST_CASE("Sum of shares")
{
  size_t t = 1;
  std::vector<NodeId> nids = {
    NodeId("0"), NodeId("1"), NodeId("2"), NodeId("3")};
  SigningSession ss(nids, {}, false);
  std::vector<size_t> indices = {0, 1, 2, 3};
  auto dd0 = from_hex(
    "0400000000000000"
    "0400000000000000"
    "010000000000000001010000000000000002010000000000000003010000000000000004"
    "0400000000000000"
    "010000000000000005010000000000000006010000000000000007010000000000000008"
    "0400000000000000"
    "01000000000000000901000000000000000A01000000000000000B01000000000000000C"
    "0400000000000000"
    "01000000000000000D01000000000000000E01000000000000000F010000000000000010"
    "0000000000000000");
  std::vector<BigNum> expected0 = {
    BigNum(6), BigNum(8), BigNum(10), BigNum(12)};
  const uint8_t* data = dd0.data();
  size_t sz = dd0.size();
  auto deal0 = std::make_shared<SigningDeal>(data, sz);

  auto dd1 = from_hex(
    "0400000000000000"
    "0400000000000000"
    "010000000000000005010000000000000006010000000000000007010000000000000008"
    "0400000000000000"
    "01000000000000000901000000000000000A01000000000000000B01000000000000000C"
    "0400000000000000"
    "01000000000000000D01000000000000000E01000000000000000F010000000000000010"
    "0400000000000000"
    "010000000000000001010000000000000002010000000000000003010000000000000004"
    "0000000000000000");
  std::vector<BigNum> expected1 = {
    BigNum(14), BigNum(16), BigNum(18), BigNum(20)};
  data = dd1.data();
  sz = dd1.size();
  auto deal1 = std::make_shared<SigningDeal>(data, sz);

  std::map<size_t, std::vector<uint8_t>> decrypted_shares = {
    {indices[0], deal0->serialise()}, {indices[1], deal1->serialise()}};

  auto sums = ss.sum_shares(nids[0], decrypted_shares);
  REQUIRE(sums.size() == expected0.size());

  for (size_t i = 0; i < expected0.size(); i++)
  {
    REQUIRE(sums[i] == expected0[i]);
  }

  sums = ss.sum_shares(nids[1], decrypted_shares);
  REQUIRE(sums.size() == expected1.size());
  for (size_t i = 0; i < expected1.size(); i++)
  {
    REQUIRE(sums[i] == expected1[i]);
  }
}

std::map<NodeId, std::vector<uint8_t>> public_keys;

void setup(
  size_t num_nodes,
  bool defensive,
  std::vector<NodeId>& nids,
  std::vector<NodeState<NodeId>>& nodes)
{
  for (size_t i = 0; i < num_nodes; i++)
  {
    nids.push_back(NodeId(std::to_string(i)));
  }

  for (size_t i = 0; i < num_nodes; i++)
  {
    nodes.push_back(NodeState(nids[i]));
    public_keys[nids[i]] = nodes.back().node_key.public_key_pem;
  }
}

Identity sample(
  bool defensive,
  std::vector<NodeId>& nids,
  std::vector<NodeState<NodeId>>& nodes)
{
  SamplingSession s(nids, defensive);

  INFO("Prepare deals");
  for (size_t i = 0; i < s.lower_threshold(); i++)
  {
    s.encrypted_deals[s.get_node_index(nodes[i].nid)] =
      s.mk_deal(nodes[i].nid, nodes[i].node_key, public_keys);
  }

  INFO("All nodes validate shares");
  for (auto& node : nodes)
  {
    REQUIRE_NOTHROW(
      s.encrypted_reshares[s.get_node_index(node.nid)] = s.mk_resharing(
        node.nid, node.x, node.x_witness, node.node_key, public_keys));

    if (s.batched_commits.empty())
      s.batched_commits =
        s.encrypted_reshares[s.get_node_index(node.nid)].batched_commits;
  }

  INFO("All nodes deposit their public key shares");
  for (auto& node : nodes)
  {
    REQUIRE_NOTHROW(
      s.open_keys[s.get_node_index(node.nid)] = s.mk_open_key(
        node.nid,
        node.x,
        node.x_witness,
        node.node_key,
        public_keys,
        node.identity.x_commits));
  }

  INFO("All nodes compute the same public key");
  {
    auto& node0 = nodes[0];
    std::string ref;
    REQUIRE_NOTHROW(
      ref = s.compute_public_key(
        node0.nid, node0.identity.x_commits, node0.identity.public_key));
    for (size_t i = 1; i < nodes.size(); i++)
    {
      auto& node = nodes[i];
      std::string npk;
      REQUIRE_NOTHROW(
        npk = s.compute_public_key(
          node.nid, node.identity.x_commits, node.identity.public_key));
      REQUIRE(npk == ref);
    }
  }

  INFO("All nodes have key shares");
  for (auto& node : nodes)
  {
    REQUIRE(node.x != BigNum::zero());
    REQUIRE(node.x_witness != BigNum::zero());
    REQUIRE(!node.identity.public_key.empty());
    REQUIRE(!node.identity.x_commits.empty());
  }

  return nodes[0].identity;
}

Identity reshare(
  bool defensive,
  std::vector<NodeId>& nids,
  std::vector<NodeId>& nids_next,
  std::vector<NodeState<NodeId>>& nodes,
  Identity& identity)
{
  assert(!nodes.empty());
  assert(!identity.public_key.empty());
  assert(!identity.x_commits.empty());

  // LOG_DEBUG_FMT("previous x_commits: {}", identity.x_commits);

  ResharingSession s(identity, nids, nids_next, defensive);

  INFO("Old nodes prepare deals");
  for (size_t i = 0; i < s.lower_threshold();)
  {
    if (std::find(nids.begin(), nids.end(), nodes[i].nid) != nids.end())
    {
      s.encrypted_deals[s.get_node_index(nodes[i].nid)] =
        s.mk_deal(nodes[i].nid, nodes[i].node_key, public_keys);
      i++;
    }
  }

  INFO("Old nodes produce reshares");
  for (auto& node : nodes)
  {
    if (std::find(nids.begin(), nids.end(), node.nid) != nids.end())
    {
      REQUIRE_NOTHROW(
        s.encrypted_reshares[s.get_node_index(node.nid)] = s.mk_resharing(
          node.nid, node.x, node.x_witness, node.node_key, public_keys));

      if (s.batched_commits.empty())
        s.batched_commits =
          s.encrypted_reshares[s.get_node_index(node.nid)].batched_commits;
    }
  }

  INFO("Update commitments");
  for (auto& node : nodes)
  {
    if (
      std::find(nids_next.begin(), nids_next.end(), node.nid) ==
      nids_next.end())
    {
      // Retiring nodes clear their state.
      node.x = BigNum::zero();
      node.x_witness = BigNum::zero();
      node.identity.public_key.clear();
      node.identity.x_commits.clear();
    }
    else
    {
      // The other nodes update their commitments.
      REQUIRE_NOTHROW(s.update_commitments(
        node.nid,
        node.node_key,
        node.public_keys,
        node.x,
        node.x_witness,
        node.identity));
    }
  }

  INFO("All except retiring nodes have key shares");
  for (auto& node : nodes)
  {
    if (
      std::find(nids_next.begin(), nids_next.end(), node.nid) !=
      nids_next.end())
    {
      REQUIRE(node.x != BigNum::zero());
      REQUIRE(node.x_witness != BigNum::zero());
      REQUIRE(!node.identity.public_key.empty());
    }
  }

  return identity;
}

void sign(
  bool defensive,
  std::vector<NodeId>& nids,
  std::vector<NodeState<NodeId>>& nodes,
  Identity& identity,
  bool verify = true)
{
  INFO("Start signing sesssion");
  std::vector<uint8_t> message = {1, 2, 3};
  SigningSession ss(nids, message, defensive);

  INFO("Prepare deals");
  for (size_t i = 0; i < ss.lower_threshold(); i++)
  {
    if (std::find(nids.begin(), nids.end(), nodes[i].nid) != nids.end())
    {
      ss.encrypted_deals[ss.get_node_index(nodes[i].nid)] =
        ss.mk_deal(nodes[i].nid, nodes[i].node_key, public_keys);
    }
  }

  INFO("All nodes deposit their OpenKs");
  for (auto& node : nodes)
  {
    if (std::find(nids.begin(), nids.end(), node.nid) != nids.end())
    {
      REQUIRE_NOTHROW(
        ss.openks[node.nid] =
          ss.mk_openk(node.nid, node.node_key, public_keys));
    }
  }

  INFO("All nodes deposit their signature shares");
  for (auto& node : nodes)
  {
    if (std::find(nids.begin(), nids.end(), node.nid) != nids.end())
    {
      BigNum r_cache = BigNum::zero();
      REQUIRE_NOTHROW(
        ss.signature_shares[node.nid] = ss.mk_signature_share(
          node.nid,
          node.x,
          node.x_witness,
          node.node_key,
          public_keys,
          r_cache));
    }
  }

  INFO("All nodes compute the signature");
  for (auto& node : nodes)
  {
    if (std::find(nids.begin(), nids.end(), node.nid) != nids.end())
    {
      std::vector<uint8_t> sig;
      BigNum r_cache = BigNum::zero();

      REQUIRE_NOTHROW(
        sig = ss.mk_signature(
          node.nid,
          node.node_key,
          public_keys,
          r_cache,
          identity.x_commits,
          identity));

      if (verify)
      {
        REQUIRE(ss.check_signature(sig, identity.public_key));
      }
    }
  }
}

TEST_CASE("Sample sign")
{
  for (size_t t = 1; t <= 3; t++)
  {
    std::vector<NodeId> nids;
    std::vector<NodeState<NodeId>> nodes;

    size_t num_nodes = 3 * t + 1;
    setup(num_nodes, false, nids, nodes);
    auto identity = sample(false, nids, nodes);
    sign(false, nids, nodes, identity);
  }
}

TEST_CASE("Sample sign non-t")
{
  // t == 1 -> n == [1, 2, 3], 4, 5, 6
  // t == 2 -> n == 7, 8, 9
  // t == 3 -> n == 10, 11, 12
  // t == 4 -> n == 13
  for (size_t num_nodes : {3, 5, 6, 8, 11})
  {
    std::vector<NodeId> nids;
    std::vector<NodeState<NodeId>> nodes;
    setup(num_nodes, false, nids, nodes);
    auto identity = sample(false, nids, nodes);
    sign(false, nids, nodes, identity);
  }
}

TEST_CASE("Sample sign defensively")
{
  size_t t = 3;
  std::vector<NodeId> nids;
  std::vector<NodeState<NodeId>> nodes;

  size_t num_nodes = 3 * t + 1;
  setup(num_nodes, true, nids, nodes);
  auto identity = sample(true, nids, nodes);
  sign(true, nids, nodes, identity);
}

TEST_CASE("Sample reshare sign")
{
  size_t t = 1;
  std::vector<NodeId> nids;
  std::vector<NodeState<NodeId>> nodes;

  size_t num_nodes = 3 * t + 1;
  setup(num_nodes, false, nids, nodes);
  auto identity = sample(false, nids, nodes);
  sign(false, nids, nodes, identity, true);

  std::vector<NodeId> next_nids = nids;
  next_nids.back() = NodeId(std::to_string(nids.size()));

  nodes.push_back(NodeState(next_nids.back()));
  public_keys[next_nids.back()] = nodes.back().node_key.public_key_pem;

  identity = reshare(false, nids, next_nids, nodes, identity);
  nids = next_nids;

  sign(false, nids, nodes, identity, true);
}

void run_bench(bool defensive, size_t num_signatures)
{
  for (size_t t = 1; t < 5; t++)
  {
    std::vector<NodeId> nids;
    std::vector<NodeState<NodeId>> nodes;

    auto before = std::chrono::high_resolution_clock::now();
    setup(3 * t + 1, defensive, nids, nodes);
    auto identity = sample(defensive, nids, nodes);
    auto after = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff_id_establishment = after - before;

    before = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < num_signatures; i++)
    {
      sign(defensive, nids, nodes, identity, false);
    }
    after = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> diff_signatures = after - before;

    LOG_INFO_FMT(
      "t={} n={} defensive={}; "
      "ID establishment: {:.2f}sec, "
      "{} signatures: {:.2f}sec, "
      "sig/sec: {:.2f}",
      t,
      nodes.size(),
      defensive,
      diff_id_establishment.count(),
      num_signatures,
      diff_signatures.count(),
      num_signatures / diff_signatures.count());
  }
}

TEST_CASE("Signing benchmark non-defensive")
{
  run_bench(false, 10);
}

TEST_CASE("Signing benchmark defensive")
{
  run_bench(true, 10);
}

typedef struct TestStore_
{
  std::map<NodeId, std::vector<uint8_t>> public_keys;
  std::map<size_t, SamplingSession<NodeId>> sampling_sessions;
  std::map<size_t, SigningSession<NodeId>> signing_sessions;
  std::map<size_t, ResharingSession<NodeId>> resharing_sessions;
  Identity current_identity;
} TestStore;

class TestRequestAdapter : public RequestAdapter<NodeId>
{
protected:
  NodeId nid;
  TestStore& store;

public:
  TestRequestAdapter(const NodeId& nid, TestStore& store) :
    RequestAdapter<NodeId>(),
    nid(nid),
    store(store)
  {}

  virtual ~TestRequestAdapter() {}

  virtual bool submit_registration(
    const std::vector<uint8_t>& public_key) const override
  {
    store.public_keys[nid] = public_key;
    return true;
  }

  virtual uint64_t sample(
    const std::vector<NodeId>& config,
    bool defensive,
    uint64_t app_id = 0) const override
  {
    size_t id = store.sampling_sessions.size();
    store.sampling_sessions.emplace(
      id, SamplingSession(config, defensive, app_id));
    return id;
  }

  virtual bool submit_sampling_deal(
    uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
  {
    store.sampling_sessions[session_id].add_deal(nid, encrypted_deal);
    return true;
  }
  virtual bool submit_sampling_resharing(
    uint64_t session_id,
    const EncryptedResharing& encrypted_resharing) const override
  {
    store.sampling_sessions[session_id].add_resharing(nid, encrypted_resharing);
    return true;
  }
  virtual bool submit_open_key(
    uint64_t session_id, const OpenKey& open_key) const override
  {
    store.sampling_sessions[session_id].add_open_key(nid, open_key);
    return true;
  }
  virtual bool submit_identity(
    uint64_t session_id, const Identity& identity) const override
  {
    store.current_identity = identity;
    return true;
  }

  virtual uint64_t sign(
    const std::vector<NodeId>& config,
    const std::vector<uint8_t>& message,
    bool defensive,
    uint64_t app_id = 0) const override
  {
    size_t id = store.signing_sessions.size();
    store.signing_sessions.emplace(
      id, SigningSession(config, message, defensive, app_id));
    return id;
  }

  virtual bool submit_signing_deal(
    uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
  {
    store.signing_sessions[session_id].add_deal(nid, encrypted_deal);
    return true;
  }
  virtual bool submit_openk(
    uint64_t session_id, const OpenK& openk) const override
  {
    store.signing_sessions[session_id].add_openk(nid, openk);
    return true;
  }
  virtual bool submit_signature_share(
    uint64_t session_id, const SignatureShare& signature_share) const override
  {
    store.signing_sessions[session_id].signature_shares[nid] = signature_share;
    return true;
  }
  virtual bool submit_signature(
    uint64_t session_id, const std::vector<uint8_t>& signature) const override
  {
    auto& s = store.signing_sessions[session_id];
    if (s.signature.empty())
    {
      s.signature = signature;
    }
    return true;
  }

  virtual uint64_t reshare(
    const Identity& current_identity,
    const std::vector<NodeId>& config,
    const std::vector<NodeId>& next_config,
    bool defensive,
    uint64_t app_id = 0) const override
  {
    size_t id = store.resharing_sessions.size();
    store.resharing_sessions.emplace(
      id,
      ResharingSession(
        current_identity, config, next_config, defensive, app_id));
    return id;
  }

  virtual bool submit_resharing_deal(
    uint64_t session_id, const EncryptedDeal& encrypted_deal) const override
  {
    store.resharing_sessions[session_id].add_deal(nid, encrypted_deal);
    return true;
  }
  virtual bool submit_resharing_resharing(
    uint64_t session_id,
    const EncryptedResharing& encrypted_resharing) const override
  {
    store.resharing_sessions[session_id].add_resharing(
      nid, encrypted_resharing);
    return true;
  }
  virtual bool complete_resharing(uint64_t session_id) const override
  {
    return true;
  }
};

class TestContext : public SplitIdentity::Context<NodeId>
{
public:
  TestContext(
    const NodeId& nid,
    std::shared_ptr<RequestAdapter<NodeId>> request_adapter,
    bool defensive) :
    SplitIdentity::Context<NodeId>(nid, request_adapter, defensive)
  {}
  TestContext(TestContext&) = delete;
  virtual ~TestContext() {}

  std::map<uint64_t, SigningSessionCache> signing_session_state;
  std::map<uint64_t, ResharingSessionCache> resharing_session_state;
  std::map<uint64_t, SamplingSessionCache> sampling_session_state;

  virtual std::optional<SigningSessionCache> get_local_signing_state(
    uint64_t id) const override
  {
    auto sid = signing_session_state.find(id);
    if (sid == signing_session_state.end())
      return SigningSessionCache();
    else
      return sid->second;
  }

  virtual void set_local_signing_state(
    uint64_t id, const std::optional<SigningSessionCache>& state) override
  {
    if (state.has_value())
      signing_session_state[id] = *state;
    else
      signing_session_state.erase(id);
  }

  virtual std::optional<ResharingSessionCache> get_local_resharing_state(
    uint64_t id) const override
  {
    auto sid = resharing_session_state.find(id);
    if (sid == resharing_session_state.end())
      return ResharingSessionCache();
    else
      return sid->second;
  }

  virtual void set_local_resharing_state(
    uint64_t id, const std::optional<ResharingSessionCache>& state) override
  {
    if (state.has_value())
      resharing_session_state[id] = *state;
    else
      resharing_session_state.erase(id);
  }

  virtual std::optional<SamplingSessionCache> get_local_sampling_state(
    uint64_t id) const override
  {
    auto sid = sampling_session_state.find(id);
    if (sid == sampling_session_state.end())
      return SamplingSessionCache();
    else
      return sid->second;
  }

  virtual void set_local_sampling_state(
    uint64_t id, const std::optional<SamplingSessionCache>& state) override
  {
    if (state.has_value())
      sampling_session_state[id] = *state;
    else
      sampling_session_state.erase(id);
  }
};

std::chrono::duration<double> run_to_completion(
  std::vector<std::shared_ptr<TestContext>>& contexts,
  std::function<bool(std::shared_ptr<TestContext>)> f)
{
  auto before = std::chrono::high_resolution_clock::now();
  bool did_something = true;
  do
  {
    did_something = false;
    for (const auto& ctx : contexts)
    {
      if (f(ctx))
      {
        did_something = true;
      }
    }
  } while (did_something);
  auto after = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> diff = after - before;
  return diff;
}

static void run_contextual(
  size_t t,
  size_t num_signatures,
  bool with_resharing,
  bool defensive,
  bool check_signatures)
{
  TestStore store;
  NodeId nid;

  size_t num_nodes = 3 * t + 1;
  std::vector<NodeId> nids;

  INFO("Set up nids and contexts");
  for (size_t i = 0; i < num_nodes; i++)
  {
    nids.push_back(NodeId(std::to_string(99 - i)));
  }

  std::vector<std::shared_ptr<TestContext>> contexts;
  for (const auto& nid : nids)
  {
    std::shared_ptr<RequestAdapter<NodeId>> request_adapter =
      std::static_pointer_cast<RequestAdapter<NodeId>>(
        std::make_shared<TestRequestAdapter>(nid, store));
    contexts.push_back(
      std::make_shared<TestContext>(nid, request_adapter, defensive));
  }

  INFO("Register public keys");
  for (const auto& ctx : contexts)
  {
    ctx->register_public_key();
    for (const auto& ctx2 : contexts)
    {
      ctx2->on_public_key_update(ctx->nid, ctx->public_key());
    }
  }

  std::chrono::duration<double> sample_time;
  INFO("Sample initial identity");
  {
    uint64_t session_id = contexts[0]->sample(nids);

    sample_time = run_to_completion(
      contexts, [&store, session_id](std::shared_ptr<TestContext> ctx) {
        return ctx->on_sampling_update(
          session_id, store.sampling_sessions[session_id]);
      });

    for (const auto& ctx : contexts)
    {
      REQUIRE(!ctx->state.identity.public_key.empty());
      REQUIRE(!ctx->state.identity.x_commits.empty());
      REQUIRE(ctx->state.x_witness != BigNum::zero());
      REQUIRE(ctx->state.x != BigNum::zero());
    }
  }

  Identity identity = contexts[0]->state.identity;

  std::chrono::duration<double> signing_time;
  INFO("Sign messages");
  {
    auto before = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < num_signatures; i++)
    {
      uint64_t session_id = contexts[0]->sign(nids, {0, 1, 2});

      run_to_completion(
        contexts, [&store, session_id](std::shared_ptr<TestContext> ctx) {
          return ctx->on_signing_update(
            session_id, store.signing_sessions[session_id]);
        });

      auto& s = store.signing_sessions[session_id];
      REQUIRE(!s.signature.empty());
      if (check_signatures)
        REQUIRE(s.check_signature(s.signature, identity.public_key));

#ifdef CHECK_SESSION_SIZE
      nlohmann::json j;
      to_json(j, s);
      std::string js = j.dump();
      LOG_DEBUG_FMT(
        "session: t={}, n={} sz={}:", t, contexts.size(), js.size(), js);
#endif
    }

    auto after = std::chrono::high_resolution_clock::now();
    signing_time = after - before;
  }

  LOG_INFO_FMT(
    "t={} n={} defensive={}; "
    "ID establishment: {:.2f}sec, "
    "{} signatures: {:.2f}sec, "
    "sig/sec: {:.2f} (contextual)",
    t,
    contexts.size(),
    defensive,
    sample_time.count(),
    num_signatures,
    signing_time.count(),
    num_signatures / signing_time.count());

  if (!with_resharing)
  {
    return;
  }

  INFO("Reshare: remove last node and add a new one");
  {
    std::vector<NodeId> next_nids = nids;
    NodeId new_nid = std::to_string(nids.size());
    next_nids.pop_back();
    next_nids.push_back(NodeId(new_nid));
    std::shared_ptr<RequestAdapter<NodeId>> request_adapter =
      std::static_pointer_cast<RequestAdapter<NodeId>>(
        std::make_shared<TestRequestAdapter>(new_nid, store));
    auto new_ctx =
      std::make_shared<TestContext>(new_nid, request_adapter, defensive);
    contexts.push_back(new_ctx);
    new_ctx->register_public_key();

    for (const auto& ctx : contexts)
    {
      ctx->on_public_key_update(new_nid, new_ctx->public_key());
    }

    INFO("Reshare: run resharing protocol");
    uint64_t session_id = contexts[0]->reshare(nids, next_nids);

    run_to_completion(
      contexts, [&store, session_id](std::shared_ptr<TestContext> ctx) {
        return ctx->on_resharing_update(
          session_id, store.resharing_sessions[session_id]);
      });

    nids = next_nids;
  }

  INFO("Sign more messages");
  {
    for (size_t i = 0; i < num_signatures; i++)
    {
      uint64_t session_id = contexts[0]->sign(nids, {4, 5, 6});

      run_to_completion(
        contexts, [&store, session_id](std::shared_ptr<TestContext> ctx) {
          return ctx->on_signing_update(
            session_id, store.signing_sessions[session_id]);
        });

      auto& s = store.signing_sessions[session_id];
      REQUIRE(!s.signature.empty());
      REQUIRE(s.check_signature(s.signature, identity.public_key));
    }
  }
}

TEST_CASE("Contextual signing")
{
  for (size_t t = 1; t <= 3; t++)
  {
    run_contextual(t, 1, true, false, true);
  }
}

TEST_CASE("Contextual signing defensive")
{
  for (size_t t = 1; t <= 3; t++)
  {
    run_contextual(t, 1, true, true, true);
  }
}

TEST_CASE("Contextual benchmark")
{
  for (auto defensive : {false, true})
  {
    for (size_t t = 1; t <= 3; t++)
    {
      run_contextual(t, 10, true, defensive, false);
    }
  }
}

int main(int argc, char** argv)
{
  doctest::Context context;
  context.applyCommandLine(argc, argv);
  //#if !defined(NDEBUG) && defined(VERBOSE_LOGGING)
  // logger::config::level() = logger::Level::DEBUG;
  //#endif
  return context.run();
}