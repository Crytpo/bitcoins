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

#ifndef TLS_AES_CBC_HMAC_SHA1_H
#define TLS_AES_CBC_HMAC_SHA1_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "aes128-cbc.h"
#include "hmac-sha1.h"
#include "tls.h"

/// This header provides an implementation of the encryption and decryption of
/// application data records for TLS 1.2 (RFC 5246, see
/// https://tools.ietf.org/html/rfc5246 for details).

/// Oracle simulating application data record encryption and decryption for
/// TLS 1.2 using AES128-CBC-HMAC-SHA1 as cipher suite.
class tls12_aes_cbc_hmac_sha1
{
public:
  typedef aes128_cbc block_cipher;
  typedef hmac_sha1 hmac;
  typedef std::array<uint8_t, hmac::block_size> hmac_key;
  typedef std::array<uint8_t, block_cipher::key_size> block_cipher_key;
  typedef std::array<uint8_t, block_cipher::key_size> initialization_vector;

  /// TLSCipherText for a generic block cipher consisting of a type, version,
  /// length, the IV and the encrypted fragment.
  struct record
  {
    record_layer_header header;      /// Record header
    initialization_vector iv;        /// IV
    std::vector<uint8_t> ciphertext; /// Ciphertext fragment

    bool operator==(const record& other) const;
    bool operator!=(const record& other) const;
  };

private:
  block_cipher encrypter_;
  block_cipher decrypter_;
  hmac_key hmac_key_;

  /// Compute HMAC tag.
  ///
  /// \param header record layer header
  /// \param plaintext the plaintext
  /// \param plaintext_size size of the plaintext
  /// \returns HMAC tag
  hmac::digest_storage compute_hmac(const record_layer_header& header, const uint8_t* plaintext,
                                    const uint16_t plaintext_size) const;

public:
  /// Instantiate with random AES key and random HMAC key
  tls12_aes_cbc_hmac_sha1();
  /// Instantiate with given AES and HMAC key.
  tls12_aes_cbc_hmac_sha1(const block_cipher_key& bc_key, const hmac_key& hm_key);

  virtual ~tls12_aes_cbc_hmac_sha1();

  /// Create an encrypted record for the given cipher text. If the optional iv is
  /// given, it shall be used as IV, otherwise a random IV is generated.
  record encrypt(const uint8_t* plaintext, uint16_t size,
                 const initialization_vector* iv = nullptr);
  /// Decrypt an encrypted record and store the data in plaintext if the record
  /// can be decrypted and verified.
  virtual bool decrypt(const record& record, std::vector<uint8_t>& plaintext);
};

#endif
