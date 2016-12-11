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

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>

#include "blockchain.h"
#include "io.h"
#include "attack.h"
#include "../utils/io.h"

namespace
{
  int print_usage(const std::string& name)
  {
    std::cout
        << "'" << name
        << "' usage information:\n\n"
           "generate_key [pubkey] [privkey]: generate ECDSA keys and store them files "
           "containing the public and the private key\n"
           "attack [blockchain] [target pubkey] [target privkey] [attacker pubkey] [attacker "
           "privkey] [solution block]\n"
           "verify_solution [blockchain] [target pubkey] [attacker pubkey] [solution block]\n";
    return 1;
  }

  template <class T>
  void from_str(T& t, const std::string& str)
  {
    std::istringstream iss(str);
    iss >> t;
  }

  bool read_blockckain(block_chain& bc, const std::string& filename)
  {
    std::ifstream is(filename.c_str());

    std::size_t number_of_blocks = 0;
    read(is, number_of_blocks);

    while (number_of_blocks--)
    {
      full_block b;
      read(is, b);
      if (!is)
      {
        std::cout << "Failed to read blockchain!" << std::endl;
        return false;
      }

      if (!bc.add_block(b))
      {
        std::cout << "Failed to add block to blockchain!" << std::endl;
        return false;
      }
    }

    return true;
  }
}

int main(int argc, char** argv)
{
  const std::string progname = argv[0];
  if (argc < 2)
    return print_usage(progname);

  const std::string command = argv[1];
  argv += 2;
  argc -= 2;

  if (command == "attack" && argc == 6)
  {
    const std::string blockchain_filename     = argv[0];
    const std::string target_pub_filename     = argv[1];
    const std::string target_priv_filename    = argv[2];
    const std::string attacker_pub_filename   = argv[3];
    const std::string attacker_priv_filename  = argv[4];
    const std::string sol_blockchain_filename = argv[5];

    gfp_t attacker_private_key;
    ecc_public_key_t attacker_public_key;
    {
      std::ifstream priv_is(attacker_priv_filename.c_str());
      read(priv_is, attacker_private_key);

      std::ifstream pub_is(attacker_pub_filename.c_str());
      read(pub_is, attacker_public_key);

      if (!priv_is || !pub_is)
      {
        std::cout << "Failed to read attacker keys!" << std::endl;
        return 1;
      }
    }

    block_chain bc;
    if (!read_blockckain(bc, blockchain_filename))
      return 1;

    const auto number_of_blocks = bc.size();

    ecc_public_key_t target_public_key;
    gfp_t target_private_key;

    if (!attack(bc, target_private_key, target_public_key, attacker_private_key,
                attacker_public_key))
    {
      std::cout << "Attack failed!" << std::endl;
      return 1;
    }

    const auto target_balance   = bc.get_balance(target_public_key);
    const auto attacker_balance = bc.get_balance(attacker_public_key);
    if (!attacker_balance)
    {
      std::cout << "Attacker's balance is 0!" << std::endl;
      return 1;
    }
    if (target_balance)
    {
      std::cout << "Target's balance is not 0!" << std::endl;
      return 1;
    }

    std::ofstream ofs(sol_blockchain_filename.c_str());
    write(ofs, bc.size() - number_of_blocks);
    for (auto i = number_of_blocks; i != bc.size(); ++i)
    {
      write(ofs, bc[i]);
    }
    if (!ofs)
    {
      std::cout << "Failed to write solution blocks!" << std::endl;
      return 1;
    }

    std::cout << "Attack was successful! Do not forget to commit the following files:" << std::endl;
    std::cout << "\t" << attacker_priv_filename << std::endl;
    std::cout << "\t" << attacker_pub_filename << std::endl;
    std::cout << "\t" << target_priv_filename << std::endl;
    std::cout << "\t" << target_pub_filename << std::endl;
    std::cout << "\t" << sol_blockchain_filename << std::endl;
  }
  else if (command == "generate_key" && argc == 2)
  {
    const std::string pubkey_filename = argv[0];
    const std::string priv_filename   = argv[1];

    gfp_t private_key;
    ecc_public_key_t public_key;
    ecdsa_generate_key(private_key, public_key);

    std::ofstream pub_os(pubkey_filename.c_str());
    write(pub_os, public_key);

    std::ofstream priv_os(priv_filename.c_str());
    write(priv_os, private_key);

    if (!pub_os || !priv_os)
    {
      std::cout << "Failed to write keys to disk!" << std::endl;
      return 1;
    }
  }
  else if (command == "verify_solution" && argc == 4)
  {
    // [blockchain] [target pubkey] [attacker pubkey] [solution block]
    const std::string blockchain_filename     = argv[0];
    const std::string targetuser_filename     = argv[1];
    const std::string attacker_pub_filename   = argv[2];
    const std::string sol_blockchain_filename = argv[3];

    ecc_public_key_t attacker_public_key;
    {
      std::ifstream pub_is(attacker_pub_filename.c_str());
      read(pub_is, attacker_public_key);

      if (!pub_is)
      {
        std::cout << "Failed to read attacker keys!" << std::endl;
        return 1;
      }
    }

    ecc_public_key_t target_public_key;
    {
      std::ifstream pub_is(targetuser_filename.c_str());
      read(pub_is, target_public_key);

      if (!pub_is)
      {
        std::cout << "Failed to read target keys!" << std::endl;
        return 1;
      }
    }

    block_chain bc;
    if (!read_blockckain(bc, blockchain_filename))
      return 1;

    const auto target_balance = bc.get_balance(target_public_key);

    if (!read_blockckain(bc, sol_blockchain_filename))
      return 1;

    const auto target_balance_2 = bc.get_balance(target_public_key);
    const auto attacker_balance = bc.get_balance(attacker_public_key);

    if (target_balance_2)
      return 1;
    if (target_balance != attacker_balance)
      return 1;
  }
  else
    return print_usage(progname);
}
