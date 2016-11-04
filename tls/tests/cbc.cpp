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

#include "../aes128-cbc.h"

#include <algorithm>
#include <iterator>
#include <vector>
#include <cstring>

#include <check.h>

namespace
{
  // http://www.inconteam.com/software-development/41-encryption/55-aes-test-vectors

  constexpr uint8_t aes128_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  constexpr uint8_t aes128_iv_0[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
  constexpr uint8_t aes128_plain_0[] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
  constexpr uint8_t aes128_cipher_0[] = {0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
                                         0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d};

  constexpr uint8_t aes128_plain_1[] = {0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};
  constexpr uint8_t aes128_cipher_1[] = {0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
                                         0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2};

  constexpr uint8_t aes128_plain_2[] = {0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                                        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef};
  constexpr uint8_t aes128_cipher_2[] = {0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b,
                                         0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16};

  template <class C>
  bool test_encrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* data,
                    const uint8_t* expected, std::size_t size = C::block_size)
  {
    C cipher(key, iv);

    std::vector<uint8_t> storage(size, 0);
    cipher.encrypt(storage.data(), data, size);

    return std::memcmp(storage.data(), expected, size) == 0;
  }

  template <class C>
  bool test_decrypt(const uint8_t* key, const uint8_t* iv, const uint8_t* data,
                    const uint8_t* expected, std::size_t size = C::block_size)
  {
    C cipher(key, iv);

    std::vector<uint8_t> storage(size, 0);
    cipher.decrypt(storage.data(), data, size);

    return std::memcmp(storage.data(), expected, size) == 0;
  }

  template <class C>
  bool test_key_iv_wipe(const uint8_t* key, const uint8_t* iv, const uint8_t* data,
                        const uint8_t* expected, std::size_t size = C::block_size)
  {
    std::array<uint8_t, C::key_size> key_storage;
    std::copy(key, key + C::key_size, key_storage.begin());

    std::array<uint8_t, C::iv_size> iv_storage;
    std::copy(iv, iv + C::iv_size, iv_storage.begin());

    C encrypter(key_storage.data(), iv_storage.data()),
        decrypter(key_storage.data(), iv_storage.data());

    std::fill(key_storage.begin(), key_storage.end(), 0);
    std::fill(iv_storage.begin(), iv_storage.end(), 0);

    std::vector<uint8_t> storage(size, 0);
    encrypter.encrypt(storage.data(), data, size);

    if (std::memcmp(storage.data(), expected, size) != 0)
      return false;

    decrypter.decrypt(storage.data(), expected, size);
    return std::memcmp(storage.data(), data, size) == 0;
  }
}

START_TEST(test_encrypt_0)
{
  ck_assert_uint_eq(
      test_encrypt<aes128_cbc>(aes128_key, aes128_iv_0, aes128_plain_0, aes128_cipher_0), true);
}
END_TEST

START_TEST(test_decrypt_0)
{
  ck_assert_uint_eq(
      test_decrypt<aes128_cbc>(aes128_key, aes128_iv_0, aes128_cipher_0, aes128_plain_0), true);
}
END_TEST

START_TEST(test_encrypt_1)
{
  ck_assert_uint_eq(
      test_encrypt<aes128_cbc>(aes128_key, aes128_cipher_0, aes128_plain_1, aes128_cipher_1), true);
}
END_TEST

START_TEST(test_decrypt_1)
{
  ck_assert_uint_eq(
      test_decrypt<aes128_cbc>(aes128_key, aes128_cipher_0, aes128_cipher_1, aes128_plain_1), true);
}
END_TEST

START_TEST(test_encrypt_2)
{
  ck_assert_uint_eq(
      test_encrypt<aes128_cbc>(aes128_key, aes128_cipher_1, aes128_plain_2, aes128_cipher_2), true);
}
END_TEST

START_TEST(test_decrypt_2)
{
  ck_assert_uint_eq(
      test_decrypt<aes128_cbc>(aes128_key, aes128_cipher_1, aes128_cipher_2, aes128_plain_2), true);
}
END_TEST

START_TEST(test_encrypt_3)
{
  std::vector<uint8_t> plain, cipher;
  std::copy(std::begin(aes128_plain_0), std::end(aes128_plain_0), std::back_inserter(plain));
  std::copy(std::begin(aes128_plain_1), std::end(aes128_plain_1), std::back_inserter(plain));
  std::copy(std::begin(aes128_plain_2), std::end(aes128_plain_2), std::back_inserter(plain));

  std::copy(std::begin(aes128_cipher_0), std::end(aes128_cipher_0), std::back_inserter(cipher));
  std::copy(std::begin(aes128_cipher_1), std::end(aes128_cipher_1), std::back_inserter(cipher));
  std::copy(std::begin(aes128_cipher_2), std::end(aes128_cipher_2), std::back_inserter(cipher));

  ck_assert_uint_eq(
      test_encrypt<aes128_cbc>(aes128_key, aes128_iv_0, plain.data(), cipher.data(), plain.size()),
      true);
}
END_TEST

START_TEST(test_decrypt_3)
{
  std::vector<uint8_t> plain, cipher;
  std::copy(std::begin(aes128_plain_0), std::end(aes128_plain_0), std::back_inserter(plain));
  std::copy(std::begin(aes128_plain_1), std::end(aes128_plain_1), std::back_inserter(plain));
  std::copy(std::begin(aes128_plain_2), std::end(aes128_plain_2), std::back_inserter(plain));

  std::copy(std::begin(aes128_cipher_0), std::end(aes128_cipher_0), std::back_inserter(cipher));
  std::copy(std::begin(aes128_cipher_1), std::end(aes128_cipher_1), std::back_inserter(cipher));
  std::copy(std::begin(aes128_cipher_2), std::end(aes128_cipher_2), std::back_inserter(cipher));

  ck_assert_uint_eq(
      test_decrypt<aes128_cbc>(aes128_key, aes128_iv_0, cipher.data(), plain.data(), cipher.size()),
      true);
}
END_TEST

START_TEST(test_encrypt_decrypt_with_key_iv_wipe)
{
  ck_assert_uint_eq(
      test_key_iv_wipe<aes128_cbc>(aes128_key, aes128_iv_0, aes128_plain_0, aes128_cipher_0), true);
}
END_TEST

int main()
{
  Suite* suite = suite_create("AES-CBC");

  TCase* tcase = tcase_create("encrypt");
  tcase_add_test(tcase, test_encrypt_0);
  tcase_add_test(tcase, test_encrypt_1);
  tcase_add_test(tcase, test_encrypt_2);
  tcase_add_test(tcase, test_encrypt_3);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("decrypt");
  tcase_add_test(tcase, test_decrypt_0);
  tcase_add_test(tcase, test_decrypt_1);
  tcase_add_test(tcase, test_decrypt_2);
  tcase_add_test(tcase, test_decrypt_3);
  suite_add_tcase(suite, tcase);

  tcase = tcase_create("wipe");
  tcase_add_test(tcase, test_encrypt_decrypt_with_key_iv_wipe);
  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  srunner_run_all(suite_runner, CK_VERBOSE);
  int number_failed = srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return !number_failed ? EXIT_SUCCESS : EXIT_FAILURE;
}
