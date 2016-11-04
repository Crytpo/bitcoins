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

#include "hmac-sha1.h"

hmac_sha1::hmac_sha1(const uint8_t* key, std::size_t keysize)
{
  std::array<uint64_t, block_size / sizeof(uint64_t)> rkey = {0};
  if (keysize > block_size)
  {
    hash ctx;
    ctx.update(key, keysize);
    const auto key_digest = ctx.digest();
    std::memcpy(rkey.data(), key_digest.data(), digest_size);
  }
  else
    std::memcpy(rkey.data(), key, keysize);

  for (std::size_t s = 0; s < rkey.size(); ++s)
    rkey[s] ^= UINT64_C(0x3636363636363636);
  ctx_i_.update(reinterpret_cast<const uint8_t*>(rkey.data()), block_size);

  for (std::size_t s = 0; s < rkey.size(); ++s)
    rkey[s] ^= UINT64_C(0x3636363636363636) ^ UINT64_C(0x5c5c5c5c5c5c5c5c);
  ctx_o_.update(reinterpret_cast<const uint8_t*>(rkey.data()), block_size);
}

void hmac_sha1::update(const uint8_t* bytes, std::size_t size)
{
  ctx_i_.update(bytes, size);
}

hmac_sha1::digest_storage hmac_sha1::digest()
{
  ctx_o_.update(ctx_i_.digest().data(), digest_size);
  return ctx_o_.digest();
}
