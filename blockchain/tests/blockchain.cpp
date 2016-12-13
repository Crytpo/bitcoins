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

#include "../blockchain.h"
#include "../../ecclib/eccp/eccp.h"
#include "../../ecclib/gfp/gfp.h"
#include "../../tls/tests/helpers.h"
#include "../ecclib-glue.h"
#include "../transaction.h"

#include <string>
#include <vector>

#include <check.h>

namespace
{
  std::uint8_t hex2uint8(char input)
  {
    if (input >= '0' && input <= '9')
      return input - '0';
    else if (input >= 'A' && input <= 'F')
      return input - 'A' + 10;
    else if (input >= 'a' && input <= 'f')
      return input - 'a' + 10;

    throw std::invalid_argument("Invalid input!");
  }

  sha2::digest_storage operator"" _sha2(const char* s, std::size_t l)
  {
    sha2::digest_storage ret{};
    if (l != sizeof(sha2::digest_storage) * 2)
      throw std::invalid_argument("Invalid input!");

    for (std::size_t i = 0; i != l; i += 2)
    {
      ret[i / 2] = hex2uint8(s[i]) * 16 + hex2uint8(s[i + 1]);
    }

    return ret;
  }

  uint_t hex2uint(const char*& s)
  {
    uint_t r = 0;
    for (std::size_t i = 0; i != sizeof(r); ++i, s += 2)
    {
      r |= hex2uint8(s[0]) * 16 + hex2uint8(s[1]);
      if (i != sizeof(r) - 1)
        r <<= 8;
    }
    return r;
  }

  ecdsa_signature_t operator"" _sig(const char* s, std::size_t l)
  {
    ecdsa_signature_t ret{};
    if (l != sizeof(gfp_t) * 4)
      throw std::invalid_argument("Invalid input!");

    for (auto& x : ret.r)
      x = hex2uint(s);
    for (auto& x : ret.s)
      x = hex2uint(s);

    return ret;
  }

  gfp_t private_key;
  ecc_public_key_t public_key;

  void init_keys()
  {
    gfp_gen_halving(private_key, secp256_params.order_n_data.gfp_one, &secp256_params.order_n_data);
    eccp_jacobian_point_multiply_L2R_DA(&public_key, &secp256_params.base_point, private_key,
                                        &secp256_params);

    if (secp256_params.prime_data.montgomery_domain)
    {
      gfp_montgomery_to_normal(public_key.x, public_key.x, &secp256_params.prime_data);
      gfp_montgomery_to_normal(public_key.y, public_key.y, &secp256_params.prime_data);
    }
  }

  full_block b1_valid()
  {
    full_block fb{{{},
                   "93b3a42f39dde7439d870b5d7b4bd388d30be66e6d87f73ba809f9c7010fe3d0"_sha2,
                   "16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2},
                  {},
                  {{}, {{public_key, 100}}, 1}};
    return fb;
  }

  full_block b2_valid()
  {
    transaction_input ti{"16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2, 0,
                         "0a758404a96e47e23c7e2e1777335dd8daa97dd4275c93212392f5801cba7ddb"
                         "8618dae3301bdd4a85653a35a8d99a5aa97e615d54d99c8e34ee0a094fd5ef99"_sig};
    transaction t{{ti}, {{public_key, 50}, {public_key, 50}}, 2};

    full_block fb{{"00717474e7b7f268cdc9c40b397626ae30ce169b4bb317dfcaf016cd067e89b2"_sha2,
                   "d77ae8ef23784029f168c183b80b0f55efb73c109eb0532919baf2354124721b"_sha2,
                   "bf25ebf712000edfaaea7233e0f770146e263518188e553bae3b36090dda1c96"_sha2},
                  {t},
                  {{}, {{public_key, 50}}, 3}};

    return fb;
  }

  full_block b1_invalid1()
  {
    full_block fb{{{},
                   "ff9d6f16de7acfb51fc9cf4c95c84007698738747dd9183c7ff6feff91b341f1"_sha2,
                   "2395d495afcc203def993262e55083bf15e70a9087b525df607b87cbb2147a54"_sha2},
                  {},
                  {{}, {{public_key, 101}}, 1}};
    return fb;
  }

  full_block b1_invalid2()
  {
    full_block fb{{{},
                   "93b3a42f39dde7439d870b5d7c4bd388d30be66e6d87f73ba809f9c7010fe3d0"_sha2,
                   "16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2},
                  {},
                  {{}, {{public_key, 100}}, 1}};
    return fb;
  }

  full_block b1_invalid3()
  {
    full_block fb{{{},
                   "93b3a42f39dde7439d870b5d7b4bd388d30be66e6d87f73ba809f9c7010fe3d0"_sha2,
                   "16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2},
                  {},
                  {{}, {{public_key, 99}}, 1}};

    return fb;
  }

  full_block b1_invalid4()
  {
    full_block fb{{{0x01},
                   "eb3e8b5d5a26cb4c1fda892da0ce2c46d8fced913b3b160bd419760f37457c99"_sha2,
                   "16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2},
                  {},
                  {{}, {{public_key, 100}}, 1}};
    return fb;
  }

  full_block b2_invalid1()
  {
    transaction_input ti{"16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2, 0,
                         "0a758404a96e47e23c7e2e1777335dd8daa97dd4275c93212392f5801cba7ddb"
                         "8618dae3301bdd4a85653a35a8d99a5aa97e615d54d99c8e34ee0a094fd5ef99"_sig};
    transaction t{{ti}, {{public_key, 50}, {public_key, 50}}, 2};

    full_block fb{{"00717474e7b7f268cdc9c40b397626ae30ce169b4bb317dfcaf016cd067e89b2"_sha2,
                   "4c88e0d83c631cf92b7cd570654e32e0be5d1ec1ad66e0d111770d32ff5f4ba9"_sha2,
                   "64398e7533e986b7919c223cea20ec7b8e1c3c02ff276d6f92d6222fdf40776f"_sha2},
                  {t, t},
                  {{}, {{public_key, 50}}, 3}};

    return fb;
  }

  full_block b3_invalid1()
  {
    transaction_input ti{"16b05efd13ff22b3dae61ef4baf431fb37c624395440620fe6ec220044a2ec8c"_sha2, 0,
                         "0a758404a96e47e23c7e2e1777335dd8daa97dd4275c93212392f5801cba7ddb"
                         "8618dae3301bdd4a85653a35a8d99a5aa97e615d54d99c8e34ee0a094fd5ef99"_sig};
    transaction t{{ti}, {{public_key, 50}, {public_key, 50}}, 4};

    full_block fb{{"006608503ed1229f7d1a8abd485048cb24bbda994b3f3edc6136c6a107951b20"_sha2,
                   "6480493475622fed8419646d032f6499f85e4bb9c6358cb5265adc699158ffb0"_sha2,
                   "786e5b78f5aa8255736643cf5b2854e70b07bd0d4c2ebe9d710ea66738ae4ba8"_sha2},
                  {t},
                  {{}, {{public_key, 50}}, 5}};

    return fb;
  }
}

START_TEST(genesis_valid1)
{
  block_chain bc;
  const full_block fb = b1_valid();

  ck_assert_uint_eq(bc.get_balance(public_key), 0);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), true);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.get_balance(public_key), 100);
}
END_TEST

START_TEST(genesis_invalid1)
{
  block_chain bc;
  const full_block fb = b1_invalid1();

  ck_assert_uint_eq(bc.get_balance(public_key), 0);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.get_balance(public_key), 0);
}
END_TEST

START_TEST(genesis_invalid2)
{
  block_chain bc;
  const full_block fb = b1_invalid2();

  ck_assert_uint_eq(bc.get_balance(public_key), 0);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.get_balance(public_key), 0);
}
END_TEST

START_TEST(genesis_invalid3)
{
  block_chain bc;
  const full_block fb = b1_invalid3();

  ck_assert_uint_eq(bc.get_balance(public_key), 0);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.get_balance(public_key), 0);
}
END_TEST

START_TEST(genesis_invalid4)
{
  block_chain bc;
  const full_block fb = b1_invalid4();

  ck_assert_uint_eq(bc.get_balance(public_key), 0);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.get_balance(public_key), 0);
}
END_TEST

START_TEST(nongenesis_valid1_valid2)
{
  block_chain bc;
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(b1_valid()), true);
  ck_assert_uint_eq(bc.add_block(b2_valid()), true);
  ck_assert_uint_eq(bc.size(), 2);
  ck_assert_uint_eq(bc.get_balance(public_key), 150);
}
END_TEST

START_TEST(nongenesis_valid1_twice)
{
  block_chain bc;
  const full_block fb = b1_valid();

  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(fb), true);
  ck_assert_uint_eq(bc.add_block(fb), false);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.get_balance(public_key), 100);
}
END_TEST

START_TEST(nongenesis_valid1_invalid2)
{
  block_chain bc;
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(b1_valid()), true);
  ck_assert_uint_eq(bc.add_block(b2_invalid1()), false);
  ck_assert_uint_eq(bc.size(), 1);
  ck_assert_uint_eq(bc.get_balance(public_key), 100);
}
END_TEST

START_TEST(nongenesis_valid1_valid2_invalid3)
{
  block_chain bc;
  ck_assert_uint_eq(bc.size(), 0);
  ck_assert_uint_eq(bc.add_block(b1_valid()), true);
  ck_assert_uint_eq(bc.add_block(b2_valid()), true);
  ck_assert_uint_eq(bc.add_block(b3_invalid1()), false);
  ck_assert_uint_eq(bc.size(), 2);
  ck_assert_uint_eq(bc.get_balance(public_key), 150);
}
END_TEST

int main()
{
  Suite* suite = suite_create("Blockchain");

  TCase* tcase = tcase_create("Genesis block");
  tcase_set_timeout(tcase, 0);
  tcase_add_checked_fixture(tcase, init_keys, NULL);
  tcase_add_test(tcase, genesis_valid1);
  tcase_add_test(tcase, genesis_invalid1);
  tcase_add_test(tcase, genesis_invalid2);
  tcase_add_test(tcase, genesis_invalid3);
  tcase_add_test(tcase, genesis_invalid4);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("Non-genesis blocks");
  tcase_set_timeout(tcase, 0);
  tcase_add_checked_fixture(tcase, init_keys, NULL);
  tcase_add_test(tcase, nongenesis_valid1_valid2);
  tcase_add_test(tcase, nongenesis_valid1_twice);
  tcase_add_test(tcase, nongenesis_valid1_invalid2);
  tcase_add_test(tcase, nongenesis_valid1_valid2_invalid3);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
