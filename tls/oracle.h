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

#ifndef ORACLE_H
#define ORACLE_H

#include "clocks.h"
#include "tls-aes-cbc-hmac-sha1.h"
#include <cstdint>
#include <vector>

/// Base class for decryption oracle implementations
class oracle
{
public:
  typedef tls12_aes_cbc_hmac_sha1 ciphersuite;
  typedef ciphersuite::record record;

  virtual ~oracle();

  /// Request a random ciphertext record for a plaintext of the given size.
  ///
  /// @param size size of the plaintext
  /// @return ciphertext record of plaintext of given size
  virtual record request_challenge(uint16_t size) = 0;
  /// Request the challenge ciphertext.
  ///
  /// @return challenge ciphertext
  virtual record request_ciphertext() = 0;

  /// Decrypt an encrypted record and store the data in plaintext if the record
  /// can be decrypted and verified.
  ///
  /// @param record ciphertext record to be decrypted
  /// @return whether the decryption was successful and the timing of the
  ///         operation, in case of an irrecoverable error the timinig is 0
  virtual std::pair<bool, uint64_t> decrypt(const record& record) = 0;
};

/// Local oracle. Performs all requests in the same process.
class local_oracle : public oracle
{
public:
  enum clock_type
  {
    RDTSC
  };

private:
  ciphersuite ciphersuite_;
  clock_type ct_;
  rdtsc_clock tsc_clock;

public:
  local_oracle(const ciphersuite::block_cipher_key& key, const ciphersuite::hmac_key& hmac_key,
               clock_type ct);
  virtual ~local_oracle();

  virtual std::pair<bool, uint64_t> decrypt(const record& record);
  virtual record request_challenge(uint16_t size);
  virtual record request_ciphertext();
};

/// Remote oracle. Sends all requests to a separate process.
class remote_oracle : public oracle
{
  int fd_;

public:
  /// Instantiate oracle running remotely available via a UNIX domain socket of
  /// the given name.
  remote_oracle(const char* socket_name);
  virtual ~remote_oracle();

  /// Stop the remote oracle.
  void stop();
  /// Check if connection was established and no socket error occurred.
  explicit operator bool() const;

  virtual std::pair<bool, uint64_t> decrypt(const record& record);
  virtual record request_ciphertext();
  virtual record request_challenge(uint16_t size);
};

#endif
