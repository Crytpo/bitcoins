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

#ifndef BLOCKCHAIN_BLOCKCHAIN_H
#define BLOCKCHAIN_BLOCKCHAIN_H

#include "../tls/sha2.h"
#include "transaction.h"

#include <cmath>

/// Blockchain for KUcoin.
class block_chain
{
public:
  /// Compute the difficulty based on the number of blocks.
  ///
  /// @param number_of_blocks current number of blocks in the chain
  /// @return current difficulty
  static constexpr std::size_t difficulty(std::size_t number_of_blocks)
  {
    return static_cast<std::size_t>(std::log(number_of_blocks + 1) / std::log(100)) + 1;
  }

  /// Add a block to the block chain with the given transactions and the reward
  /// transaction. In case the block is invalid, false is returned.
  ///
  /// Valid blocks are:
  /// - previous matches the hash of the previous block
  /// - if the block is the first block, previous must be all zeroes
  /// - root must be the root hash for the Merkle tree with reward
  ///   and all transactions in the same order as they appear in transactions
  /// - reward transactions have empty inputs and exactly one output
  /// - the output of reward transactions may not exeed 100
  /// - all other transactions need to be valid
  /// - unless the block is the first one, the block must consist of at least
  ///   one transaction.
  ///
  /// Valid transactions are:
  /// - The hash in transaction input must refer to valid transactions recorded
  ///   in any previous block.
  /// - The output index in the transaction input must refer to a valid output
  ///   in the referenced transaction.
  /// - The (hash,index) pair must be unique.
  /// - The signature must be a valid signature for (hash, index) matching the
  ///   public key in the referenced output.
  /// - Each amount in output needs to be positive.
  /// - The total amount of all outputs must match the total amount of all
  ///   inputs.
  ///
  /// @param fb the block to process
  /// @return true if the block is valid and was added to the blockchain, false
  /// otherwise
  bool add_block(const full_block& fb);

  /// Get balance of a user.
  ///
  /// Counts all unspent coins of the given key.
  ///
  /// @param public_key public key of a user
  /// @return number of unspent coins of the user
  uint32_t get_balance(const ecc_public_key_t& public_key) const;

  /// Access the information on the i-th block.
  ///
  /// @param index of the block
  /// @return return full information of the given block
  const full_block& operator[](std::size_t index) const;

  /// Return number of stored blocks
  ///
  /// @return number of stored blocks
  std::size_t size() const;
};

#endif
