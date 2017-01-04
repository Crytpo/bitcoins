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

#ifndef TRANSACTION_H
#define TRANSACTION_H

#include "../ecclib/protocols/protocols.h"
#include "../tls/sha2.h"

#include <ctime>
#include <vector>

/// Represents a transaction input
///
/// It references a previous transaction via its hash and the output index. The
/// signature must be a valid signature for the redeemed transaction output.
///
/// When hashing transaction inputs, hash transaction_hash || output_index ||
/// signature.
struct transaction_input
{
  sha2::digest_storage transaction_hash;
  uint32_t output_index;
  ecdsa_signature_t signature;
};

/// Represents a transaction output
///
/// The ECDSA public key specifies the user that is able to redeem the
/// transaction. The amount specifies the number of redemable coins.
///
/// When hashing transaction outputs, hash target || amount.
struct transaction_output
{
  ecc_public_key_t target;
  uint32_t amount;
};

/// Represents a transaction
///
/// A transaction consists of inputs and outputs such that:
/// * the redeemed amount exactly matches the spent amount
/// * all signatures of the inputs are valid
/// * inputs do not refer to already redeemed transactions
///
/// When hashing transactions, hash outputs || inputs || timestamp.
struct transaction
{
  std::vector<transaction_input> inputs;
  std::vector<transaction_output> outputs;
  std::time_t timestamp;
};

/// Header of a block
///
/// It contains the hash of the previos block, contains a seed used to compute
/// proof of work, and the root hash of the Merkle tree consisting of all
/// transactions.
///
/// In case the block is the first block, previous must be all zeroes.
///
/// When hashing blocks, hash previous || seed || root_hash twice.
struct block
{
  sha2::digest_storage previous;
  sha2::digest_storage seed;
  sha2::digest_storage root_hash;
};

/// A full block
///
/// A full block consists of the header, all its transactions and a reward
/// transaction for the mainer. A block is valid if:
///
/// * The transaction reward is non-zero and less than or equal 100.
/// * If it is the first block, it may not contain any transactions.
/// * If is is not the first block, it must contain transactions.
/// * The root hash stored in the header must equal the the root hash of the
///   Merkle tree consisting of hash(reward) || hash(transaction_1) ||
///   ... hash(transaction_n)
struct full_block
{
  ::block block;
  std::vector<transaction> transactions;
  transaction reward;
};

#endif
