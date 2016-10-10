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

#include "tls-ascon.h"
#include "endian.h"
#include "random.h"

bool tls12_ascon::record::operator==(const record& other) const
{
  if (header.type != other.header.type)
    return false;
  if (header.version.major != other.header.version.major)
    return false;
  if (header.version.minor != other.header.version.minor)
    return false;
  if (header.length != other.header.length)
    return false;
  if (explicit_nonce != other.explicit_nonce)
    return false;
  return ciphertext == other.ciphertext;
}

bool tls12_ascon::record::operator!=(const record& other) const
{
  return !(*this == other);
}

tls12_ascon::tls12_ascon(const key_storage& key, const incrementing_nonce& nonce)
{
  // \todo initialize with given key
}

tls12_ascon::record tls12_ascon::encrypt(uint64_t sequence_number,
                                         const std::vector<uint8_t>& plaintext)
{
  /// \todo Implement ciphertext record generation for given plaintext.
  /// The nonce has to be incremented after an successful encryption.
  return record();
}

bool tls12_ascon::decrypt(uint64_t sequence_number, const record& record,
                          std::vector<uint8_t>& plaintext)
{
  /// \todo Implement decryption for the given record.
  /// If decryption was successful return true, otherwise return false.
  return false;
}
