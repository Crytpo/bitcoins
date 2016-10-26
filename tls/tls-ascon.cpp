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
    : nonce_(nonce), ascon_(key) { }

tls12_ascon::record tls12_ascon::encrypt(uint64_t sequence_number,
                                         const std::vector<uint8_t>& plaintext)
{
  // header data
  content_type type = TLS_APPLICATION_DATA;
  protocol_version version = { .major = TLSv1_2_MAJOR, .minor = TLSv1_2_MINOR };
  uint16_t plaintext_length = plaintext.size();
  uint16_t header_length = incrementing_nonce::explicit_size
      + ascon128::ciphertext_size(plaintext.size());

  // flip everything due to order of bytes (network order = big endian)
  // easier with std::reverse_copy, but not sure if allowed
  uint64_t be_seq = htob(sequence_number);
  uint8_t be_type = htob((uint8_t) type);
  uint16_t be_version = htob(*(uint16_t*) &version); // fancy
  uint16_t be_plen = htob(plaintext_length);
  uint16_t be_length = htob(header_length);

  // create additional data which is needed for the encryption
  size_t ad_len = sizeof(be_seq) + sizeof(be_type) + sizeof(be_version)
      + sizeof(be_plen);
  std::vector<uint8_t> associated_data(ad_len, 0);

  std::copy((uint8_t*) &be_seq, (uint8_t*) &be_seq + sizeof(be_seq),
      associated_data.data());
  std::copy((uint8_t*) &be_type, (uint8_t*) &be_type + sizeof(be_type),
      associated_data.data() + sizeof(be_seq));
  std::copy((uint8_t*) &be_version, (uint8_t*) &be_version + sizeof(be_version),
      associated_data.data() + sizeof(be_seq) + sizeof(be_type));
  std::copy((uint8_t*) &be_plen, (uint8_t*) &be_plen + sizeof(be_plen),
      associated_data.data() + (ad_len - sizeof(be_plen)));

  // encrypt plaintext with ascon128, nonce and additional data
  std::vector<uint8_t> ciphertext;
  ascon_.encrypt(ciphertext, plaintext, nonce_.nonce(), associated_data);

  // create the record with the header data, encrypted fragment and the nonce
  // important: everything in network byte order (= big endian)
  record encrypted_record = {
    .header = {
          .type = be_type,
          .version = *(protocol_version*)&be_version, // big endian, but object?
          .length = be_length
        },
    .explicit_nonce = nonce_.explicit_nonce(),
    .ciphertext = ciphertext
  };

  // increment counter in nonce for next encryption
  ++nonce_;

  return encrypted_record;
}

bool tls12_ascon::decrypt(uint64_t sequence_number, const record& record,
                          std::vector<uint8_t>& plaintext)
{
  // create additional data (flip stuff that is not read from the record)
  uint64_t be_seq = htob(sequence_number);
  uint16_t be_plen = ascon128::plaintext_size(record.ciphertext.size());
  be_plen = htob(be_plen);

  size_t ad_len = sizeof(be_seq) + sizeof(record.header.type)
      + sizeof(record.header.version) + sizeof(be_plen);
  std::vector<uint8_t> associated_data(ad_len, 0);

  std::copy((uint8_t*) &be_seq, (uint8_t*) &be_seq + sizeof(be_seq),
      associated_data.data());
  std::copy((uint8_t*) &record.header,
      (uint8_t*) &record.header + sizeof(record.header.type) + sizeof(record.header.version),
      associated_data.data() + sizeof(be_seq));
  std::copy((uint8_t*) &be_plen, (uint8_t*) &be_plen + sizeof(be_plen),
        associated_data.data() + (ad_len - sizeof(be_plen)));

  // build used nonce (implicit from saved nonce and explicit from record)
  std::array<uint8_t, incrementing_nonce::nonce_size> nonce;
  std::array<uint8_t, incrementing_nonce::implicit_size> implicit_nonce =
      nonce_.implicit_nonce();

  std::copy(implicit_nonce.begin(), implicit_nonce.end(), nonce.begin());
  std::copy(record.explicit_nonce.begin(), record.explicit_nonce.end(),
      nonce.begin() + incrementing_nonce::implicit_size);

  // decrypt the ciphertext
  bool ret_val = ascon_.decrypt(plaintext, record.ciphertext, nonce,
      associated_data);

  return ret_val;
}
