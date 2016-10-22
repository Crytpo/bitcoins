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

#include "hmac-sha2.h"
#include "sha2.h"

// H(K, m) = sha2( (K' XOR O) || sha2((K' XOR I) || m ) )
// H(K, m) = sha2( outer_padding || sha2(inner_padding || m) )
// ----------------------------------------------------------------------------
// K' = K || 0x00 * (block_size - keysize)    if keysize <= block_size
//    = sha2(K) || 0x00 * 32                  if keysize > block_size
// O  = 0x5C * block_size
// I  = 0x36 * block_size
// m  = message data
hmac_sha2::hmac_sha2(const uint8_t* key, std::size_t keysize)
{
  std::array<uint8_t, block_size> derived_key;
  derived_key.fill(0);

  if (keysize <= block_size) // fill with 0's
  {
    std::copy(&key[0], &key[0] + keysize, derived_key.data());
  }
  else // if (keysize > block_size) -> shorter hash value and pad with 0's
  {
    sha2 hash_function;
    hash_function.update(key, keysize);
    digest_storage hashed_key = hash_function.digest();

    std::copy(hashed_key.begin(), hashed_key.end(), derived_key.data());
  }

  // calculate outer and inner paddings
  for (size_t index = 0; index < block_size; ++index)
  {
    inner_padding_[index] = 0x36 ^ derived_key[index];
    outer_padding_[index] = 0x5C ^ derived_key[index];
  }

  // add inner_padding to the data of the inner hash function
  inner_hash_.update(inner_padding_.data(), inner_padding_.size());
}

void hmac_sha2::update(const uint8_t* bytes, std::size_t size)
{
  // simply append data to the data of the inner hash function
  // automatically done by sha2.update(...)
  inner_hash_.update(bytes, size);
}

hmac_sha2::digest_storage hmac_sha2::digest()
{
  // calculate inner hash value using the set inner padding and data
  digest_storage inner_hash_value = inner_hash_.digest();

  // calculate overall hash value using the outer padding and the inner hash
  sha2 outer_hash;
  outer_hash.update(outer_padding_.data(), outer_padding_.size());
  outer_hash.update(inner_hash_value.data(), inner_hash_value.size());

  return outer_hash.digest();
}
