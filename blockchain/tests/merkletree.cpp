/******************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.2, 1st of October 2016
**
** This framework may only be used within the IT-Security exercises 2016. Only
** students that are formally registered within TUGRAZ-online may use it until
** 30th of June 2016. After that date, licensees have the duty to safely
** delete the software framework.
**
** This license does not grant you any rights to re-distribute the software,
** to change the license, to grant access to other individuals, and to
** commercially use the software.
**
** This software is distributed WITHOUT ANY WARRANTY; without even the implied
** warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
**
** If you are interested in a more reasonable license, please use the contact
** information above.
**
******************************************************************************/

#include "../merkletree.h"
#include "../../tls/tests/helpers.h"

#include <string>
#include <vector>

#include <check.h>

namespace
{
  sha2::digest_storage hash(const std::string& data)
  {
    sha2 h;
    h.update(reinterpret_cast<const uint8_t*>(data.c_str()), data.size());
    return h.digest();
  }
}

START_TEST(root_hash_4)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"), hash("b"), hash("c"), hash("d")}};

  merkle_tree mt(hashes);
  const std::string rh = digest_to_string(mt.root_hash());

  ck_assert_str_eq(rh.c_str(), "14ede5e8e97ad9372327728f5099b95604a39593cac3bd38a343ad76205213e7");
}
END_TEST

START_TEST(root_hash_3)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"), hash("b"), hash("c")}};

  merkle_tree mt(hashes);
  const std::string rh = digest_to_string(mt.root_hash());

  ck_assert_str_eq(rh.c_str(), "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe");
}
END_TEST

START_TEST(proof_4)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"), hash("b"), hash("c"), hash("d")}};

  merkle_tree mt(hashes);

  const auto proof = mt.proof(hash("a"));
  ck_assert_uint_eq(proof.size(), 2);

  ck_assert_uint_eq(proof[0].pos, merkle_tree::left);
  ck_assert_uint_eq(proof[1].pos, merkle_tree::left);

  std::string digest = digest_to_string(proof[0].digest);
  ck_assert_str_eq(digest.c_str(),
                   "3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d");

  digest = digest_to_string(proof[1].digest);
  ck_assert_str_eq(digest.c_str(),
                   "bffe0b34dba16bc6fac17c08bac55d676cded5a4ade41fe2c9924a5dde8f3e5b");
}
END_TEST

START_TEST(proof_4_2)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"), hash("b"), hash("c"), hash("d")}};

  merkle_tree mt(hashes);
  merkle_tree mt2(mt.root_hash());

  const auto proof = mt.proof(hash("a"));
  ck_assert_uint_eq(proof.size(), 2);

  ck_assert_uint_eq(mt.verify(hash("a"), proof), true);
  ck_assert_uint_eq(mt2.verify(hash("a"), proof), true);

  ck_assert_uint_eq(mt.verify(hash("b"), proof), false);
  ck_assert_uint_eq(mt2.verify(hash("b"), proof), false);
}
END_TEST

START_TEST(mt_size)
{
  std::vector<sha2::digest_storage> hashes{{hash("a"), hash("b"), hash("c"), hash("d"), hash("e")}};
  merkle_tree mt_5(hashes);

  const auto proof = mt_5.proof(hash("e"));

  hashes.push_back(hashes[4]);
  merkle_tree mt_6(hashes);

  hashes.push_back(hashes[4]);
  merkle_tree mt_7(hashes);

  hashes.push_back(hashes[4]);
  merkle_tree mt_8(hashes);

  const std::string rh_5 = digest_to_string(mt_5.root_hash());
  const std::string rh_6 = digest_to_string(mt_6.root_hash());
  const std::string rh_7 = digest_to_string(mt_7.root_hash());
  const std::string rh_8 = digest_to_string(mt_8.root_hash());

  ck_assert_str_eq(rh_5.c_str(), rh_6.c_str());
  ck_assert_str_eq(rh_5.c_str(), rh_7.c_str());
  ck_assert_str_eq(rh_5.c_str(), rh_8.c_str());

  ck_assert_uint_eq(mt_5.verify(hash("e"), proof), true);
  ck_assert_uint_eq(mt_6.verify(hash("e"), proof), true);
  ck_assert_uint_eq(mt_7.verify(hash("e"), proof), true);
  ck_assert_uint_eq(mt_8.verify(hash("e"), proof), true);
}
END_TEST

int main()
{
  Suite* suite = suite_create("Merkle tree");

  TCase* tcase = tcase_create("Merkle tree");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, root_hash_3);
  tcase_add_test(tcase, root_hash_4);
  tcase_add_test(tcase, proof_4);
  tcase_add_test(tcase, proof_4_2);
  tcase_add_test(tcase, mt_size);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
