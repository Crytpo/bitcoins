/******************************************************************************
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

#include "../hmac-sha2.h"
#include "helpers.h"

#include <check.h>

namespace
{
  // FIPS 198a A.1
  const uint8_t key_fips_1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                                0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
                                0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                                0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

  const uint8_t text_fips_1[] = {'S', 'a', 'm', 'p', 'l', 'e', ' ', '#', '1'};

  const std::string expected_fips_1 =
      "3519f0cddfa090f8ace819d9ae8501578c46920502c62baa47bfe6014864a93a";

  // FIPS 198a A.2
  const uint8_t key_fips_2[] = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
                                0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43};

  const uint8_t text_fips_2[] = {'S', 'a', 'm', 'p', 'l', 'e', ' ', '#', '2'};

  const std::string expected_fips_2 =
      "b8f20db541ea4309ca4ea9380cd0e834f71fbe9174a261380dc17eae6a3451d9";

  // FIPS 198a A.3
  const uint8_t key_fips_3[] = {
      0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e,
      0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
      0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
      0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
      0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
      0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
      0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3};

  const uint8_t text_fips_3[] = {'S', 'a', 'm', 'p', 'l', 'e', ' ', '#', '3'};

  const std::string expected_fips_3 =
      "2d7d0d7f3e52ffe89d65c978f39d555bb48b0ba48d5b6eb404654ad1afdb4ca3";

  // RFC 2202 1
  const uint8_t key_1[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
                           0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};

  const uint8_t text_1[] = {'H', 'i', ' ', 'T', 'h', 'e', 'r', 'e'};

  const std::string expected_1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

  // RFC 2202 2
  const uint8_t key_2[] = {'J', 'e', 'f', 'e'};

  const uint8_t text_2[] = {'w', 'h', 'a', 't', ' ', 'd', 'o', ' ', 'y', 'a', ' ', 'w', 'a', 'n',
                            't', ' ', 'f', 'o', 'r', ' ', 'n', 'o', 't', 'h', 'i', 'n', 'g', '?'};

  const std::string expected_2 = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

  // RFC 2202 3
  const uint8_t key_3[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

  const uint8_t text_3[] = {0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
                            0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd};

  const std::string expected_3 = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe";

  // RFC 2202 4
  const uint8_t key_4[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                           0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                           0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19};

  const uint8_t text_4[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
                            0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};

  const std::string expected_4 = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b";

  // RFC 2202 5
  const uint8_t key_5[] = {0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
                           0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c};

  const uint8_t text_5[] = {'T', 'e', 's', 't', ' ', 'W', 'i', 't', 'h', ' ',
                            'T', 'r', 'u', 'n', 'c', 'a', 't', 'i', 'o', 'n'};

  const std::string expected_5 = "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5";

  // RFC 2202 6
  const uint8_t key_6[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

  const uint8_t text_6[] = {'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r',
                            'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k',
                            '-', 'S', 'i', 'z', 'e', ' ', 'K', 'e', 'y', ' ', '-', ' ', 'H', 'a',
                            's', 'h', ' ', 'K', 'e', 'y', ' ', 'F', 'i', 'r', 's', 't'};

  const std::string expected_6 = "6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f";

  // RFC 2202 7
  const uint8_t key_7[] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                           0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};

  const uint8_t text_7[] = {
      'T', 'e', 's', 't', ' ', 'U', 's', 'i', 'n', 'g', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T',
      'h', 'a', 'n', ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'K', 'e', 'y', ' ',
      'a', 'n', 'd', ' ', 'L', 'a', 'r', 'g', 'e', 'r', ' ', 'T', 'h', 'a', 'n', ' ', 'O', 'n', 'e',
      ' ', 'B', 'l', 'o', 'c', 'k', '-', 'S', 'i', 'z', 'e', ' ', 'D', 'a', 't', 'a'};

  const std::string expected_7 = "6355ac22e890d0a3c8481a5ca4825bc884d3e7a1ff98a2fc2ac7d8e064c3b2e6";
}

START_TEST(fips_1)
{
  const auto h =
      compute_hmac<hmac_sha2>(key_fips_1, sizeof(key_fips_1), text_fips_1, sizeof(text_fips_1));
  ck_assert_str_eq(h.c_str(), expected_fips_1.c_str());
}
END_TEST

START_TEST(fips_2)
{
  const auto h =
      compute_hmac<hmac_sha2>(key_fips_2, sizeof(key_fips_2), text_fips_2, sizeof(text_fips_3));
  ck_assert_str_eq(h.c_str(), expected_fips_2.c_str());
}
END_TEST

START_TEST(fips_3)
{
  const auto h =
      compute_hmac<hmac_sha2>(key_fips_3, sizeof(key_fips_3), text_fips_3, sizeof(text_fips_3));
  ck_assert_str_eq(h.c_str(), expected_fips_3.c_str());
}
END_TEST

START_TEST(rfc2202_1)
{
  const auto h = compute_hmac<hmac_sha2>(key_1, sizeof(key_1), text_1, sizeof(text_1));
  ck_assert_str_eq(h.c_str(), expected_1.c_str());
}
END_TEST

START_TEST(rfc2202_2)
{
  const auto h = compute_hmac<hmac_sha2>(key_2, sizeof(key_2), text_2, sizeof(text_2));
  ck_assert_str_eq(h.c_str(), expected_2.c_str());
}
END_TEST

START_TEST(rfc2202_3)
{
  const auto h = compute_hmac<hmac_sha2>(key_3, sizeof(key_3), text_3, sizeof(text_3));
  ck_assert_str_eq(h.c_str(), expected_3.c_str());
}
END_TEST

START_TEST(rfc2202_4)
{
  const auto h = compute_hmac<hmac_sha2>(key_4, sizeof(key_4), text_4, sizeof(text_4));
  ck_assert_str_eq(h.c_str(), expected_4.c_str());
}
END_TEST

START_TEST(rfc2202_5)
{
  const auto h = compute_hmac<hmac_sha2>(key_5, sizeof(key_5), text_5, sizeof(text_5));
  ck_assert_str_eq(h.c_str(), expected_5.c_str());
}
END_TEST

START_TEST(rfc2202_6)
{
  const auto h = compute_hmac<hmac_sha2>(key_6, sizeof(key_6), text_6, sizeof(text_6));
  ck_assert_str_eq(h.c_str(), expected_6.c_str());
}
END_TEST

START_TEST(rfc2202_7)
{
  const auto h = compute_hmac<hmac_sha2>(key_7, sizeof(key_7), text_7, sizeof(text_7));
  ck_assert_str_eq(h.c_str(), expected_7.c_str());
}
END_TEST

START_TEST(rfc2202_1_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_1, sizeof(key_1), text_1, sizeof(text_1));
  ck_assert_str_eq(h.c_str(), expected_1.c_str());
}
END_TEST

START_TEST(rfc2202_2_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_2, sizeof(key_2), text_2, sizeof(text_2));
  ck_assert_str_eq(h.c_str(), expected_2.c_str());
}
END_TEST

START_TEST(rfc2202_3_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_3, sizeof(key_3), text_3, sizeof(text_3));
  ck_assert_str_eq(h.c_str(), expected_3.c_str());
}
END_TEST

START_TEST(rfc2202_4_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_4, sizeof(key_4), text_4, sizeof(text_4));
  ck_assert_str_eq(h.c_str(), expected_4.c_str());
}
END_TEST

START_TEST(rfc2202_5_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_5, sizeof(key_5), text_5, sizeof(text_5));
  ck_assert_str_eq(h.c_str(), expected_5.c_str());
}
END_TEST

START_TEST(rfc2202_6_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_6, sizeof(key_6), text_6, sizeof(text_6));
  ck_assert_str_eq(h.c_str(), expected_6.c_str());
}
END_TEST

START_TEST(rfc2202_7_i)
{
  const auto h = compute_hmac_i<hmac_sha2>(key_7, sizeof(key_7), text_7, sizeof(text_7));
  ck_assert_str_eq(h.c_str(), expected_7.c_str());
}
END_TEST

int main()
{
  Suite* suite = suite_create("HMAC_SHA2");

  TCase* tcase = tcase_create("FIPS");
  tcase_add_test(tcase, fips_1);
  tcase_add_test(tcase, fips_2);
  tcase_add_test(tcase, fips_3);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("RFC 2202");
  tcase_add_test(tcase, rfc2202_1);
  tcase_add_test(tcase, rfc2202_2);
  tcase_add_test(tcase, rfc2202_3);
  tcase_add_test(tcase, rfc2202_4);
  tcase_add_test(tcase, rfc2202_5);
  tcase_add_test(tcase, rfc2202_6);
  tcase_add_test(tcase, rfc2202_7);
  tcase_add_test(tcase, rfc2202_1_i);
  tcase_add_test(tcase, rfc2202_2_i);
  tcase_add_test(tcase, rfc2202_3_i);
  tcase_add_test(tcase, rfc2202_4_i);
  tcase_add_test(tcase, rfc2202_5_i);
  tcase_add_test(tcase, rfc2202_6_i);
  tcase_add_test(tcase, rfc2202_7_i);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
