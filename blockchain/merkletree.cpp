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

#include "merkletree.h"

merkle_tree::merkle_tree(const std::vector<sha2::digest_storage>& hashes)
{
  size_t n = hashes.size();

  // check if n is power of 2 and if not fill hashes with last hash until it is
  // power of 2 = only 1 bit set
  // e.g. 5?  -> 0b101 & 0b100 = 0b100 = 4 == 0 ? NO
  //      16? -> 0b10000 & 0b01111 = 0b00000 = 0 == 0 ? YES
  while ((n & (n - 1)) != 0)
    n++;
  std::vector<sha2::digest_storage> hashes_fill(n - hashes.size(), *hashes.rbegin());


  // build binary tree within vector using the following structure:
  //    https://en.wikipedia.org/wiki/Binary_tree#Arrays
  // leaf nodes l = (all nodes n + 1) / 2 => n = (l * 2) - 1
  tree_.resize(n * 2 - 1);

  // insert leaves (and fillers) into the tree (end of vector)
  auto it_tree = tree_.rbegin();
  position pos = right;

  for (ssize_t index = hashes_fill.size() - 1; index >= 0; --index)
  {
    it_tree->digest = hashes_fill[index];
    it_tree->pos = pos;

    pos = (pos == right) ? left : right;
    ++it_tree;
  }

  for (ssize_t index = hashes.size() - 1; index >= 0; --index)
  {
    it_tree->digest = hashes[index];
    it_tree->pos = pos;

    pos = (pos == right) ? left : right;
    ++it_tree;
  }

  // calculate all hashes of the tree up to the root hash
  for (ssize_t index = tree_.size() - 1; index > 0; index = index - 2)
  {
    sha2 hash;
    hash.update(tree_[index - 1].digest.data(), tree_[index - 1].digest.size());
    hash.update(tree_[index].digest.data(), tree_[index].digest.size());

    // parent = (child - 1) / 2
    tree_[(index - 1) / 2].digest = hash.digest();
    tree_[(index - 1) / 2].pos = pos;

    pos = (pos == right) ? left : right;

    /*
    // print h_l, h_r (childs) and h_lr (parent)
    std::cout << index << ": " << std::endl
              << "\t" << digest_to_string(tree_[index - 1].digest) << " - " << ((tree_[index - 1].pos == right) ? "right" : "left") << std::endl
              << "\t" << digest_to_string(tree_[index].digest) << " - " << ((tree_[index].pos == right) ? "right" : "left") << std::endl
              << "\t" << digest_to_string(tree_[(index - 1) / 2].digest) << " - " << ((tree_[(index - 1) / 2].pos == right) ? "right" : "left") << std::endl;
    */
  }

  /*
  // print whole tree
  std::cout << "Hashes: " << std::endl;
  for (auto test : hashes)
  {
    std::cout << digest_to_string(test) << std::endl;
  }

  std::cout << "Tree: " << std::endl;
  for (auto test : tree_)
  {
    std::cout << digest_to_string(test.digest) << " - "
              << ((test.pos == right) ? "right" : "left") << std::endl;
  }
  */
}

merkle_tree::merkle_tree(const sha2::digest_storage& root_hash)
{
  tree_.push_back({root_hash, left});
}

std::vector<merkle_tree::proof_node> merkle_tree::proof(const sha2::digest_storage& value) const
{
  // number of nodes in proof = number of layers until value (one node in each layer)
  std::vector<merkle_tree::proof_node> proof_nodes;

  // find index of the value
  size_t index_of_value = 0;
  for (size_t index = 0; index < tree_.size(); ++index)
  {
    if (tree_[index].digest == value)
    {
      index_of_value = index;
      break;
    }
  }

  // build proof tree (sibling nodes along the path to the value)
  for (ssize_t index = index_of_value; index > 0; index = (index - 1) / 2) // (index - 1) / 2 = index of parent
  {
    // right and left child are siblings
    int index_other_child = (tree_[index].pos == left) ? index + 1 : index - 1;

    proof_nodes.push_back( {tree_[index_other_child].digest, tree_[index].pos} ); // digest of sibling, pos of node itself
  }

  // return proof tree
  return proof_nodes;
}

bool merkle_tree::verify(const sha2::digest_storage& value,
                         const std::vector<proof_node>& proof) const
{
  sha2::digest_storage calculated_hash = value;

  // start at value and work up to root
  for (auto it_proof = proof.begin(); it_proof != proof.end(); ++it_proof)
  {
    sha2 hash;

    // calculate hash of parent H(h_l, h_r)
    // previous hash/value is either h_l or h_r depending on pos
    if (it_proof->pos == left)
    {
      hash.update(calculated_hash.data(), calculated_hash.size());
      hash.update(it_proof->digest.data(), it_proof->digest.size());
    }
    else // right
    {
      hash.update(it_proof->digest.data(), it_proof->digest.size());
      hash.update(calculated_hash.data(), calculated_hash.size());
    }

    calculated_hash = hash.digest();
  }

  // check if calculated hash matches the root hash
  return (calculated_hash == root_hash());
}

sha2::digest_storage merkle_tree::root_hash() const
{
  if (tree_.size() > 0)
    return tree_[0].digest;

  return {};
}
