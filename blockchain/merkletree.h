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

#ifndef MERKLETREE_H
#define MERKLETREE_H

#include "../tls/sha2.h"

#include <vector>

/// A Merkle tree
class merkle_tree
{
public:
  enum position
  {
    left,
    right
  };
  struct proof_node
  {
    sha2::digest_storage digest;
    position pos;
  };

  /// Initialize Merkle tree from digests.
  ///
  /// Given the vector of hashes, builds a Merkle tree where the hashes are
  /// placed in the the leaf nodes.
  ///
  /// @param hashes hashes in the leaf nodes
  merkle_tree(const std::vector<sha2::digest_storage>& hashes);
  /// Initialize Merkle tree from a root hash.
  ///
  /// In this configuration, the Merkle tree can only be used for verification.
  ///
  /// @param root_hash the root hash
  merkle_tree(const sha2::digest_storage& root_hash);

  /// Create a member ship proof for the given digest.
  ///
  /// A proof of consists of a sequence of proof_node instances, where each
  /// proof_node declares if the proven value is the left or right input to the
  /// hash function and constains the digest of the sibling.
  ///
  /// @param value digest to proof
  /// @return sequence of proof nodes or an empty sequence of the value is not
  /// contained in the tree
  std::vector<proof_node> proof(const sha2::digest_storage& value) const;
  /// Verify the membership of a given value and its proof against the root hash.
  ///
  /// @param value value to be tested
  /// @param proof proof for the given value
  /// @return true if the value is contained in the tree, i.e. the proof matches
  /// the root hash
  bool verify(const sha2::digest_storage& value, const std::vector<proof_node>& proof) const;

  /// Return root hash of the Merkle tree
  ///
  /// @return root hash
  sha2::digest_storage root_hash() const;
};

#endif
