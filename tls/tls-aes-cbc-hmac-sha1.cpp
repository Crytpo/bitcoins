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

#include "tls-aes-cbc-hmac-sha1.h"
#include "const-memcmp.h"
#include "endian.h"
#include "random.h"

#include <algorithm>
#include <cstring>

namespace
{
  constexpr uint16_t max_padding_size = 256;

  constexpr protocol_version TLSv1_2{TLSv1_2_MAJOR, TLSv1_2_MINOR};

  template <class H, class T>
  void update_hmac(H& hmac, const T& value)
  {
    hmac.update(reinterpret_cast<const uint8_t*>(&value), sizeof(T));
  }

  struct record_size_information
  {
    std::size_t plain_text_size;
    std::size_t padding_size;
    std::size_t cipher_text_length;
    std::size_t record_size;
  };

  template <class C, class H>
  constexpr std::size_t padding_length(const std::size_t plain_size)
  {
    return (C::block_size - ((plain_size + H::digest_size + 1) % C::block_size)) % C::block_size;
  }

  template <class C, class H>
  constexpr std::size_t cipher_text_length(const std::size_t plain_size)
  {
    return plain_size + H::digest_size + 1 + padding_length<C, H>(plain_size);
  }

  template <class C, class H>
  constexpr std::size_t record_size(const std::size_t plain_size)
  {
    return sizeof(record_layer_header) + C::iv_size + cipher_text_length<C, H>(plain_size);
  }

  template <class C, class H>
  constexpr record_size_information record_size_info(const std::size_t plain_size)
  {
    return record_size_information{plain_size, padding_length<C, H>(plain_size),
                                   cipher_text_length<C, H>(plain_size),
                                   record_size<C, H>(plain_size)};
  }
}

bool tls12_aes_cbc_hmac_sha1::record::operator==(const record& other) const
{
  if (header.type != other.header.type)
    return false;
  if (header.version.major != other.header.version.major)
    return false;
  if (header.version.minor != other.header.version.minor)
    return false;
  if (header.length != other.header.length)
    return false;
  if (iv != other.iv)
    return false;
  return ciphertext == other.ciphertext;
}

bool tls12_aes_cbc_hmac_sha1::record::operator!=(const record& other) const
{
  return !(*this == other);
}

tls12_aes_cbc_hmac_sha1::tls12_aes_cbc_hmac_sha1(const block_cipher_key& bc_key,
                                                 const hmac_key& hm_key)
  : hmac_key_(hm_key)
{
  encrypter_.set_key(bc_key.data());
  decrypter_.set_key(bc_key.data());
}

tls12_aes_cbc_hmac_sha1::~tls12_aes_cbc_hmac_sha1()
{
}

tls12_aes_cbc_hmac_sha1::hmac::digest_storage
tls12_aes_cbc_hmac_sha1::compute_hmac(const record_layer_header& header, const uint8_t* plaintext,
                                      const uint16_t plaintext_size) const
{
  // HMAC(sequence number || TLSCompressed.type || TLSCompressed.version ||
  // TLSCompressed.length + TLSCompressed.fragment)
  //
  // For simplicity we always assume sequence number to be 0. However, we may
  // not simply omit it.
  uint64_t sequence_number = 0;

  hmac hmac(hmac_key_.data(), hmac_key_.size());
  update_hmac(hmac, hton(sequence_number));
  update_hmac(hmac, header.type);
  update_hmac(hmac, header.version);
  update_hmac(hmac, hton(plaintext_size));
  hmac.update(plaintext, plaintext_size);
  return hmac.digest();
}

tls12_aes_cbc_hmac_sha1::record tls12_aes_cbc_hmac_sha1::encrypt(const uint8_t* plaintext,
                                                                 uint16_t size,
                                                                 const initialization_vector* iv)
{
  const auto size_info(record_size_info<block_cipher, hmac>(size));

  record result;
  // Prepare record layer header
  result.header = {TLS_APPLICATION_DATA, TLSv1_2,
                   hton<uint16_t>(size_info.cipher_text_length + block_cipher::iv_size)};

  if (iv)
    result.iv = *iv;
  else
  {
    // Generate IV.
    get_random_data(result.iv.data(), result.iv.size());
  }
  result.ciphertext.resize(size_info.cipher_text_length);

  // Prepare plaintext: plaintext || HMAC || padding
  std::vector<uint8_t> data(size_info.cipher_text_length, 0);
  auto data_walker = data.data();
  std::memcpy(data_walker, plaintext, size);
  data_walker += size;

  // Compute HMAC
  const auto hmac_tag = compute_hmac(result.header, plaintext, size);
  std::memcpy(data_walker, hmac_tag.data(), hmac_tag.size());
  data_walker += hmac::digest_size;

  // Write padding
  std::memset(data_walker, size_info.padding_size, size_info.padding_size + 1);

  // Encrypt
  encrypter_.set_iv(result.iv.data());
  encrypter_.encrypt(result.ciphertext.data(), data.data(), size_info.cipher_text_length);

  return result;
}

bool tls12_aes_cbc_hmac_sha1::decrypt(const record& record, std::vector<uint8_t>& plaintext)
{
  const uint16_t cipher_text_size = record.ciphertext.size();
  // Check basic constraints.
  if (ntoh(record.header.length) != cipher_text_size + record.iv.size())
    return false;

  // Temporary storage for decrypted data.
  std::vector<uint8_t> data(cipher_text_size, 0);

  // Decrypt.
  decrypter_.set_iv(record.iv.data());
  decrypter_.decrypt(data.data(), record.ciphertext.data(), cipher_text_size);

  // Get padding and check for valid padding pattern.
  const uint8_t padding       = data[cipher_text_size - 1];
  const std::size_t padding_1 = static_cast<std::size_t>(padding) + 1;
  bool pad_failed             = false;
  // The following code will always check the same amount of bytes regardless of
  // the padding.
  const std::size_t bound = std::min(max_padding_size, cipher_text_size);
  for (std::size_t s = 2; s <= bound; ++s)
  {
    const bool tmp = data[cipher_text_size - s] != padding;
    pad_failed |= (s <= padding_1) & tmp;
  }
  pad_failed |= padding_1 > cipher_text_size - hmac::digest_size;

  // Compute plain text size.
  const std::size_t padding_size    = pad_failed ? 0 : padding_1;
  const std::size_t plain_text_size = cipher_text_size - padding_size - hmac::digest_size;

  // Compute HMAC for the encrypted data.
  const auto hmac_tag = compute_hmac(record.header, data.data(), plain_text_size);

  // Check HMAC.
  if (const_memcmp(hmac_tag.data(), &data[plain_text_size], hmac::digest_size) != 0)
    return false;

  data.resize(plain_text_size);
  std::swap(plaintext, data);
  return true;
}
