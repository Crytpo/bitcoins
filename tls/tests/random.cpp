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

#include "../random.h"
#include "helpers.h"

#include <array>

#include <check.h>

START_TEST(simple)
{
  std::array<uint8_t, 64> data{{ 0 }};
  const auto rhs = digest_to_string(data);

  get_random_data(data.data(), data.size());

  const auto lhs = digest_to_string(data);
  ck_assert_str_ne(lhs.c_str(), rhs.c_str());
}
END_TEST

START_TEST(twice)
{
  std::array<uint8_t, 64> data{{ 0 }}, data2{{ 0 }};

  get_random_data(data.data(), data.size());
  get_random_data(data2.data(), data2.size());

  const auto lhs = digest_to_string(data);
  const auto rhs = digest_to_string(data2);
  ck_assert_str_ne(lhs.c_str(), rhs.c_str());
}
END_TEST


int main()
{
  Suite* suite = suite_create("Random");

  TCase* tcase = tcase_create("Basic");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, simple);
  tcase_add_test(tcase, twice);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
