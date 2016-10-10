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

#include "../counter.h"
#include "../endian.h"
#include <cstring>

#include <check.h>

namespace
{
  constexpr uint8_t fixed_common[]     = {0x01, 0x02, 0x03, 0x04};
  constexpr uint8_t fixed_distinct[]   = {0x05, 0x06, 0x07, 0x08};
  constexpr uint8_t fixed_distinct_2[] = {0x06, 0x07, 0x08, 0x09};
}

START_TEST(simple)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  const auto n     = nonce.nonce();
  const uint64_t c = 0;

  ck_assert_uint_eq(std::memcmp(n.data(), fixed_common, sizeof(fixed_common)), 0);
  ck_assert_uint_eq(
      std::memcmp(n.data() + sizeof(fixed_common), fixed_distinct, sizeof(fixed_distinct)), 0);
  ck_assert_uint_eq(
      std::memcmp(n.data() + sizeof(fixed_common) + sizeof(fixed_distinct), &c, sizeof(c)), 0);
}
END_TEST

START_TEST(loop)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;

  for (uint64_t i = 1; i != 0xfffff; ++i, ++nonce)
  {
    const auto n     = nonce.nonce();
    const uint64_t c = hton(i);

    ck_assert_uint_eq(std::memcmp(n.data(), fixed_common, sizeof(fixed_common)), 0);
    ck_assert_uint_eq(
        std::memcmp(n.data() + sizeof(fixed_common), fixed_distinct, sizeof(fixed_distinct)), 0);
    ck_assert_uint_eq(
        std::memcmp(n.data() + sizeof(fixed_common) + sizeof(fixed_distinct), &c, sizeof(c)), 0);
  }
}
END_TEST

START_TEST(reset)
{
  incrementing_nonce nonce(fixed_common, fixed_distinct);
  ++nonce;
  nonce.reset(fixed_distinct_2);
  const auto n     = nonce.nonce();
  const uint64_t c = 0;

  ck_assert_uint_eq(std::memcmp(n.data(), fixed_common, sizeof(fixed_common)), 0);
  ck_assert_uint_eq(
      std::memcmp(n.data() + sizeof(fixed_common), fixed_distinct_2, sizeof(fixed_distinct_2)), 0);
  ck_assert_uint_eq(
      std::memcmp(n.data() + sizeof(fixed_common) + sizeof(fixed_distinct_2), &c, sizeof(c)), 0);
}
END_TEST

int main()
{
  Suite* suite = suite_create("Nonce");

  TCase* tcase = tcase_create("Nonce");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, simple);
  tcase_add_test(tcase, loop);
  tcase_add_test(tcase, reset);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
