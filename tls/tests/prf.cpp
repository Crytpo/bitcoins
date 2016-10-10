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

#include "../prf.h"
#include "helpers.h"

#include <cstring>
#include <string>
#include <vector>

#include <check.h>

namespace
{
  constexpr uint8_t secret[] = {0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9};
  constexpr uint8_t seed[]   = {0xef, 0xee, 0xed, 0xec, 0xeb, 0xea, 0xe9, 0xe8, 0xe7, 0xe6};
  const std::string label    = "label for HMAC-PRF using HMAC-SHA2";
  const std::string expected =
      "ba04b70f8cdf554803c91ab1bfe401ae190ee2dfdfbf58546cfaef8143272721e34cea8c740e1df3224941aa3e07"
      "987bcfa0df4a3a770a55d3732b8370ea2ef3ee1df795d0228334b1c965a10d2bd48b881e6dcabaa55a25e6192883"
      "fc3fac69e83833553f1b26dc686ccb1e00f0ee2cb6afdf686b976e1b4f2a3e9bf548ef2dd93fde13fb0dd5f668bc"
      "245c2e1bc78a2d7cd542204ce5bc73f109c9bb0ca70977a7cb5d26eeac240e5868714ac84eb0c402fea6534bf508"
      "d17ea416f650d265af43c1d1a8b83fcf44c86fbaea8fd59120f5c8c523ee351a2de5026562afa0fde6b7344604b6"
      "8d257312573eef636a42a49419fe186204c60828a3adc6d10a4a5cc9e19f75820cd74c2ec4adfa8dc702b979b7e1"
      "c76e8c87aa3f0a65f4fd34e4475c8b471f759da615225b0287c736707ab1ad6221c69c747765a094c57e13175a25"
      "729eb40461f245521082d3413a72ad592672c77575aaae4359bee3d33ecbf6b247d0addfd729151358db339fd768"
      "18926ed7b1e2b3dca0117cc5a0074a16d8b4f282ddcbcd57079b27bd62500ae0f2aee2b21c1996c84ffa2b651c32"
      "f8444f6860131250c2857ee07480b5b5e41fb017304ae49052c74df9ddfb5504b6d2951467618c20120e91089326"
      "4b673fb2321c3d730e8a82bd80b615c60a00fe46c3f79c2cb4e54f9967a565a9eb3074f173dd62e3d7a6765544e4"
      "bacc1d0437be7533cc6d275745ba2254a4e74595ad7a3b5f7c5ec4e8ee430802be5d9566dbddfcc997c6ee587741"
      "76022b6eda5f4b91d9cd56b02b146682821b9c9bac77cfa6c790c2c17f05d37f0f0f47fd5d707fd33c3bd6b28549"
      "9bb28b6ea1d0ad35838e009db4876772d7426ffddd0b73de39b02fe63169e8703d5232620549825dfbd55589f82f"
      "1c87ed16e147cdba049db3750e3cbfe272bfc6fb52b1ff1c3b2114b93d34e09daae27dff2a40c0a1be3f6f24d191"
      "c1f97dae78c849d5154f561b11237b9f81c84d7468b6776f5a82e776878b9fae399faee4ce214ea29e11015f84ad"
      "0a73d4a84fe346d6a0899a8e29ab8f8750f97ad123d7b06860f9f7ee7e6b059a3dba6acc162d77629f96b10134e0"
      "c862400ab589e82f3b8f8380e6902db07f486aa44cac5945557071954631fc0168cc40552caeac1cb6cf590798c1"
      "935709d0424b4a6f795bccc629a078726c7cdb7d2b6e7010f9c2ec2f37b47713628e67a2d7bf5fbd3f47b8763608"
      "a4fe03922a65d4ae3213101cbd5c67b01714cb901464e1ba5dea1075ebd4cd95d972644fce54d8f612da26aa11b1"
      "5d8239d77797fc6e91430c2e52a5dbb3318bf4983a34db5cfb10173fcf7f7aa3ae2dff33b0adf73b89f702177806"
      "383655d9332b7dcd65d890eb97ae184a0f1f2d963df49b6768b75bbee15ac5eb412b32930b44980e31fe4ae289fc"
      "a07acf7e68820725005c85b8";
}

START_TEST(simple)
{
  hmac_prf prf(secret, sizeof(secret), label, seed, sizeof(seed));

  std::vector<uint8_t> output(expected.size() / 2);
  prf.get_output(output.data(), output.size());

  const auto outputs = digest_to_string(output);
  ck_assert_str_eq(outputs.c_str(), expected.c_str());
}
END_TEST

START_TEST(loop)
{
  hmac_prf prf(secret, sizeof(secret), label, seed, sizeof(seed));

  std::vector<uint8_t> output(expected.size() / 2);
  for (std::size_t s = 0; s != output.size(); ++s)
    prf.get_output(&output[s], 1);

  const auto outputs = digest_to_string(output);
  ck_assert_str_eq(outputs.c_str(), expected.c_str());
}
END_TEST

int main()
{
  Suite* suite = suite_create("HMAC PRF");

  TCase* tcase = tcase_create("HMAC PRF");
  tcase_set_timeout(tcase, 0);
  tcase_add_test(tcase, simple);
  tcase_add_test(tcase, loop);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
