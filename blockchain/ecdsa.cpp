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

#include "ecdsa.h"
#include "ecclib-glue.h"

#include "../ecclib/protocols/ecdsa.h"
#include "../ecclib/utils/param.h"

namespace
{
  sha2::digest_storage hash_message(const uint8_t* data, std::size_t len)
  {
    sha2 hash;
    hash.update(data, len);
    return hash.digest();
  }
}

ecdsa_signature_t ecdsa_sha2_sign(const gfp_t& private_key, const sha2::digest_storage& digest)
{
  gfp_t hashed_message;
  ecdsa_hash_to_gfp(hashed_message, digest.data(), digest.size(), &secp256_params.order_n_data);

  ecdsa_signature_t signature;
  ecdsa_sign(&signature, hashed_message, private_key, &secp256_params);

  return signature;
}

bool ecdsa_sha2_verify(const ecc_public_key_t& public_key, const ecdsa_signature_t& signature,
                       const sha2::digest_storage& digest)
{
  gfp_t hashed_message;
  ecdsa_hash_to_gfp(hashed_message, digest.data(), digest.size(), &secp256_params.order_n_data);
  return ecdsa_is_valid(&signature, hashed_message, &public_key, &secp256_params);
}

ecdsa_signature_t ecdsa_sha2_sign(const gfp_t& private_key, const uint8_t* data, std::size_t len)
{
  return ecdsa_sha2_sign(private_key, hash_message(data, len));
}

bool ecdsa_sha2_verify(const ecc_public_key_t& public_key, const ecdsa_signature_t& signature,
                       const uint8_t* data, std::size_t len)
{
  return ecdsa_sha2_verify(public_key, signature, hash_message(data, len));
}

void ecdsa_generate_key(gfp_t& private_key, ecc_public_key_t& public_key)
{
  eckeygen(private_key, &public_key, &secp256_params);
}
