/*****************************************************************************
**
** Copyright (C) 2016 Graz University of Technology
**
** Contact: itsec-team@iaik.tugraz.at
**
** IT-SECURITY LICENSE
** Version 1.1, 12th of March 2016
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

#include "../ascon128.h"
#include "../counter.h"
#include "helpers.h"

#include <algorithm>
#include <string>

#include <check.h>

namespace
{
  constexpr ascon128::key_storage key = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

  constexpr uint8_t fixed_common[]     = {0x01, 0x02, 0x03, 0x04};
  constexpr uint8_t fixed_distinct[]   = {0x05, 0x06, 0x07, 0x08};
  constexpr uint8_t fixed_distinct_2[] = {0x06, 0x07, 0x08, 0x09};

  const std::string plaintext_1 = "abcdefghijklmnoqrstuvwxyz0123456789ABCDEFGHIJKLMNOQRSTUVWXYZ";
  const std::string ad_1        = digest_to_string(plaintext_1);
  const std::string expected_1 = "92cfeb539e661d00136e31b317afee3d4e8272fd71a873eade188bdcac2ea37f9"
                                 "e5f4e2ab21247779ab9fba41670ad0d0b933837b944f3e9948fc72ccd5c8234e2"
                                 "646c73740c60c6eeb3cbc8";
}

START_TEST(encrypt_decrypt)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;
  const auto n = nonce.nonce();

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  ascon.encrypt(ciphertext, plaintext, n);
  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + ascon128::additional_size);

  std::vector<uint8_t> plaintext_2;
  const auto res = ascon.decrypt(plaintext_2, ciphertext, n);

  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(plaintext_2.size(), plaintext.size());
  ck_assert_uint_eq(plaintext[0], plaintext_2[0]);
}
END_TEST

START_TEST(encrypt_decrypt_ad)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;
  const auto n = nonce.nonce();

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext;
  ascon.encrypt(ciphertext, plaintext, n, plaintext);
  ck_assert_uint_eq(ciphertext.size(), plaintext.size() + ascon128::additional_size);

  std::vector<uint8_t> plaintext_2;
  auto res = ascon.decrypt(plaintext_2, ciphertext, n);
  ck_assert_uint_eq(res, false);

  res = ascon.decrypt(plaintext_2, ciphertext, n, plaintext);
  ck_assert_uint_eq(res, true);
  ck_assert_uint_eq(plaintext_2.size(), plaintext.size());
  ck_assert_uint_eq(plaintext[0], plaintext_2[0]);
}
END_TEST

START_TEST(encrypt_decrypt_distinct)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  ascon.encrypt(ciphertext, plaintext, nonce.nonce());
  ++nonce;
  ascon.encrypt(ciphertext_2, plaintext, nonce.nonce());

  ck_assert_uint_eq(ciphertext.size(), ciphertext_2.size());
  ck_assert_uint_eq(std::equal(ciphertext.begin(), ciphertext.end(), ciphertext_2.begin()), false);
}
END_TEST

START_TEST(encrypt_decrypt_fail)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{{'p'}};
  std::vector<uint8_t> ciphertext, ciphertext_2;
  ascon.encrypt(ciphertext, plaintext, nonce.nonce());
  ascon.encrypt(ciphertext_2, plaintext, nonce.nonce());

  ciphertext[0] += 1;
  ciphertext_2[1] += 1;

  auto res = ascon.decrypt(plaintext, ciphertext, nonce.nonce());
  ck_assert_uint_eq(res, false);

  res = ascon.decrypt(plaintext, ciphertext_2, nonce.nonce());
  ck_assert_uint_eq(res, false);
}
END_TEST

START_TEST(encrypt)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;

  ascon128 ascon(key);

  std::vector<uint8_t> plaintext{plaintext_1.begin(), plaintext_1.end()};
  std::vector<uint8_t> ad(ad_1.begin(), ad_1.end());
  std::vector<uint8_t> ciphertext;
  ascon.encrypt(ciphertext, plaintext, nonce.nonce(), ad);

  const auto c = digest_to_string(ciphertext);
  ck_assert_str_eq(c.c_str(), expected_1.c_str());
}
END_TEST

int main()
{
  Suite* suite = suite_create("Ascon");

  TCase* tcase = tcase_create("Simple");
  tcase_add_test(tcase, encrypt);
  tcase_add_test(tcase, encrypt_decrypt);
  tcase_add_test(tcase, encrypt_decrypt_ad);
  tcase_add_test(tcase, encrypt_decrypt_distinct);
  tcase_add_test(tcase, encrypt_decrypt_fail);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
