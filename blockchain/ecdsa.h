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

#ifndef BLOCKCHAIN_ECDSA_H
#define BLOCKCHAIN_ECDSA_H

#include <cstdint>

#include "../ecclib/protocols/eckeygen.h"
#include "../ecclib/types.h"
#include "../tls/sha2.h"

/// Create signature using the given private key for the given hash digest.
///
/// @param private_key ECDSA private key used to sign
/// @param digest SHA2 digest to sign
/// @return new signature for digest under private_key
ecdsa_signature_t ecdsa_sha2_sign(const gfp_t& private_key, const sha2::digest_storage& digest);
/// Verify a signature for the given hash digest under the given public key.
///
/// @param public_key ECDSA public key
/// @param signature signature to verify
/// @param digest SHA2 digest
/// @return true if the signature is valid for the given digest under public_key.
bool ecdsa_sha2_verify(const ecc_public_key_t& public_key, const ecdsa_signature_t& signature,
                       const sha2::digest_storage& digest);

/// Create signature using the given private key for the given data.
///
/// This function serves as a shortcut to hashing data yourself and calling
/// ecdsa_sha2_sign(const gfp_t&, const sha2::digest_storage&).
///
/// @param private_key ECDSA private key used to sign
/// @param data data to sign
/// @param len length of data
/// @return new signature for data under private_key
ecdsa_signature_t ecdsa_sha2_sign(const gfp_t& private_key, const uint8_t* data, std::size_t len);
/// Verify a signature for the given data under the given public key.
///
/// This function serves as a shortcut to hashing data yourself and calling
/// ecdsa_sha2_verify(const ecc_public_key_t&, const ecdsa_signature_t&, const sha2::digest_storage&).
///
/// @param public_key ECDSA public key
/// @param signature signature to verify
/// @param data data to sign
/// @param len length of data
/// @return true if the signature is valid for the given data under public_key.
bool ecdsa_sha2_verify(const ecc_public_key_t& public_key, const ecdsa_signature_t& signature,
                       const uint8_t* data, std::size_t len);

/// Generate a new ECDSA key pair
///
/// @param private_key the private key
/// @param public_key the public key
void ecdsa_generate_key(gfp_t& private_key, ecc_public_key_t& public_key);

#endif
