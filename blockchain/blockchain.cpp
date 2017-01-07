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

#include "blockchain.h"
#include "merkletree.h"

#include <algorithm>
#include <unordered_set>

#include "../tls/tests/helpers.h" // digest_to_string(...)
#include "ecclib-glue.h" // secp256_params
#include "../ecclib/eccp/eccp.h" // eccp_affine_point_compare(...)
#include "ecdsa.h" // ecdsa_sha2_verify(...)

block_chain::block_chain()
{
  hash_previous_.fill(0);
}

sha2::digest_storage block_chain::calculate_hash_transaction(const transaction& t)
{
  sha2 hash;

  for (const transaction_output& output : t.outputs)
  {
    hash.update(reinterpret_cast<const uint8_t*>(&output.target.x), sizeof(output.target.x));
    hash.update(reinterpret_cast<const uint8_t*>(&output.target.y), sizeof(output.target.y));
    hash.update(reinterpret_cast<const uint8_t*>(&output.target.identity), sizeof(output.target.identity));

    hash.update(reinterpret_cast<const uint8_t*>(&output.amount), sizeof(output.amount));
  }

  for (const transaction_input& input : t.inputs)
  {
    hash.update(input.transaction_hash.data(), input.transaction_hash.size());
    hash.update(reinterpret_cast<const uint8_t*>(&input.output_index), sizeof(input.output_index));

    hash.update(reinterpret_cast<const uint8_t*>(&input.signature.r), sizeof(input.signature.r));
    hash.update(reinterpret_cast<const uint8_t*>(&input.signature.s), sizeof(input.signature.s));
  }

  hash.update(reinterpret_cast<const uint8_t*>(&t.timestamp), sizeof(t.timestamp));

  return hash.digest();
}

bool block_chain::checkTransactions(const std::vector<transaction>& transactions)
{
  std::unordered_set<std::string> check_duplicates;
  std::vector<transaction_output*> redeemed_transactions;

  for (const transaction& t: transactions)
  {
    uint64_t amount_inputs = 0;
    uint64_t amount_outputs = 0;

    for (const transaction_input& t_in: t.inputs)
    {
      // The hash in transaction input must refer to valid transactions recorded
      // in any previous block.
      auto it_t_out = transactions_.find(digest_to_string(t_in.transaction_hash));
      if (it_t_out == transactions_.end())
        return false;

      // get corresponding block, transaction index and transaction of the output transaction
      full_block& fb = blockchain_[it_t_out->second.first];
      int64_t t_index = it_t_out->second.second;
      transaction& t_of_t_out = (t_index == -1) ? fb.reward : fb.transactions[t_index];

      // The output index in the transaction input must refer to a valid output
      // in the referenced transaction.
      if (t_in.output_index >= t_of_t_out.outputs.size())
        return false;

      transaction_output& t_out = t_of_t_out.outputs[t_in.output_index];

      // The signature must be a valid signature for (hash, index) matching the
      // public key in the referenced output.
      sha2 hash;
      hash.update(t_in.transaction_hash.data(), t_in.transaction_hash.size());
      hash.update(reinterpret_cast<const uint8_t*>(&t_in.output_index), sizeof(t_in.output_index));
      sha2::digest_storage hash_signature = hash.digest();

      if (ecdsa_sha2_verify(t_out.target, t_in.signature, hash_signature) == false)
        return false;

      // The (hash,index) pair must be unique.
      // Checked using a hashset -> emplace returns pair with a bool indicating if value already in set
      if (check_duplicates.emplace(digest_to_string(hash_signature)).second == false)
        return false;

      // sum up amount of outputs that are redeemed
      if (t_out.amount == 0) // already redeemed
        return false;

      amount_inputs = amount_inputs + t_out.amount;

      // save transaction to redeem them (set amount to 0) when everything is ok
      redeemed_transactions.push_back(&t_out);
    }


    for (const transaction_output& t_out : t.outputs)
    {
      // Each amount in output needs to be positive.
      if (t_out.amount == 0) // cannot be negative (uint)
        return false;

      // sum up amount of new outputs
      amount_outputs = amount_outputs + t_out.amount;
    }


    // The total amount of all outputs must match the total amount of all
    // inputs.
    if (amount_inputs != amount_outputs)
      return false;
  }


  // apply transactions to update blockchain (redeem transactions = set amount to 0)
  for (transaction_output* t_out : redeemed_transactions)
  {
    t_out->amount = 0;
  }

  return true;
}


bool block_chain::add_block(const full_block& fb)
{
  // previous matches the hash of the previous block
  // if the block is the first block, previous must be all zeroes
  if (fb.block.previous != hash_previous_)
    return false;

  // unless the block is the first one, the block must consist of at least one transaction
  if (std::all_of(fb.block.previous.begin(), fb.block.previous.end(), [](int i) { return i==0; }) == false
      && fb.transactions.size() == 0)
    return false;

  // reward transactions have empty inputs and exactly one output
  // TODO: blockchain.h states the above, while in the assignment description
  //       it is mentioned that it may have one output (i.e also none possible?)
  if (fb.reward.inputs.size() != 0 || fb.reward.outputs.size() != 1)
    return false;

  // the output of reward transactions may not exceed 100 (assumption: also > 0)
  if (fb.reward.outputs[0].amount > 100 || fb.reward.outputs[0].amount == 0)
    return false;

  // create merkle tree and check if calculated root hash matches given root hash
  std::vector<sha2::digest_storage> hashes_merkle;
  hashes_merkle.push_back(calculate_hash_transaction(fb.reward));
  for (transaction t : fb.transactions)
    hashes_merkle.push_back(calculate_hash_transaction(t));

  sha2::digest_storage root_hash_merkle_tree = merkle_tree(hashes_merkle).root_hash();
  if (root_hash_merkle_tree != fb.block.root_hash)
    return false;

  // calculate hash of current block for puzzle
  sha2::digest_storage hash_current_block;

  sha2 hash_block;
  hash_block.update(fb.block.previous.data(), fb.block.previous.size());
  hash_block.update(fb.block.seed.data(), fb.block.seed.size());
  hash_block.update(fb.block.root_hash.data(), fb.block.root_hash.size());
  hash_current_block = hash_block.digest();

  hash_block = sha2();
  hash_block.update(hash_current_block.data(), hash_current_block.size());
  hash_current_block = hash_block.digest();

  // check if v (seed) solves the puzzle (i.e. check if number of leading zeros of block hash matches expectation)
  size_t needed_zeros = difficulty(blockchain_.size());
  if (std::all_of(hash_current_block.begin(), hash_current_block.begin() + needed_zeros, [](int i) { return i==0; }) == false)
    return false;

  // all other transactions need to be valid
  if (checkTransactions(fb.transactions) == false)
    return false;

  // insert into linked list and save transactions
  blockchain_[digest_to_string(hash_current_block)] = fb;
  hash_previous_ = hash_current_block;

  // save all transactions for easier access and checking
  transactions_[digest_to_string(hashes_merkle[0])] = std::pair<std::string, int64_t>(digest_to_string(hash_current_block), -1);
  for (size_t t_index = 1; t_index < hashes_merkle.size(); ++t_index)
  {
    transactions_[digest_to_string(hashes_merkle[t_index])] = std::pair<std::string, int64_t>(digest_to_string(hash_current_block), (t_index - 1));
  }

  return true;
}

uint32_t block_chain::get_balance(const ecc_public_key_t& public_key) const
{
  uint32_t balance = 0;

  // if given key of output transaction matches target -> add to balance
  for (auto& blockchain_pair : blockchain_)
  {
    // reward
    if (blockchain_pair.second.reward.outputs[0].amount > 0 &&   // amount != 0 -> unredeemed/unspent coins
        eccp_affine_point_compare(&blockchain_pair.second.reward.outputs[0].target, &public_key, &secp256_params) == 0)
    {
      balance = balance + blockchain_pair.second.reward.outputs[0].amount;
    }

    // output transactions
    for (auto& t : blockchain_pair.second.transactions)
    {
      for (auto& t_out : t.outputs)
      {
        if (t_out.amount > 0 &&   // amount != 0 -> unredeemed/unspent coins
            eccp_affine_point_compare(&t_out.target, &public_key, &secp256_params) == 0)
        {
          balance = balance + t_out.amount;
        }
      }
    }
  }

  return balance;
}

const full_block& block_chain::operator[](std::size_t index) const
{
  // start at the end (end = size - 1) and to get to i'th element, we
  // have to forward (end - i) times
  // NOTE: obviously very very inefficient

  size_t size_blockchain = size();
  if (size_blockchain != 0 && index < size_blockchain) // can't return reference to nothing ?
  {
    std::string hash_block = digest_to_string(hash_previous_);
    size_t current_index = size_blockchain - 1;

    while (current_index != index)
    {
      hash_block = digest_to_string(blockchain_.at(hash_block).block.previous);
      --current_index;
    }

    return blockchain_.at(hash_block);
  }
}

std::size_t block_chain::size() const
{
  return blockchain_.size();
}
