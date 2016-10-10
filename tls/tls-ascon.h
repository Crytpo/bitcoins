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

#ifndef TLS_ASCON_H
#define TLS_ASCON_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "ascon128.h"
#include "tls.h"
#include "counter.h"

/// Oracle simulating application data record encryption and decryption for
/// TLS 1.2 using ASCON as cipher suite.
class tls12_ascon
{
public:
  typedef ascon128::key_storage key_storage;
  typedef std::array<uint8_t, incrementing_nonce::explicit_size> nonce_storage;

  /// TLSCipherText for a generic block cipher consisting of a type, version,
  /// length, the explicit part of the nonce and the encrypted fragment.
  struct record
  {
    record_layer_header header;      /// Record header
    nonce_storage explicit_nonce;    /// Nonce
    std::vector<uint8_t> ciphertext; /// Ciphertext fragment

    bool operator==(const record& other) const;
    bool operator!=(const record& other) const;
  };

  /// Instantiate with given Ascon key and nonce generator.
  tls12_ascon(const key_storage& key, const incrementing_nonce& nonce);

  /// Create an encrypted record for the given cipher text. If the optional iv is
  /// given, it shall be used as IV, otherwise a random IV is generated.
  record encrypt(uint64_t sequence_number, const std::vector<uint8_t>& plaintext);
  /// Decrypt an encrypted record and store the data in plaintext if the record
  /// can be decrypted and verified.
  bool decrypt(uint64_t sequence_number, const record& record,
                       std::vector<uint8_t>& plaintext);
};

#endif
