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

#include "io.h"

#include <iostream>

namespace
{
  // function declarations need to be available for io.h
  void read(std::istream& is, transaction_input& ti);
  void write(std::ostream& os, const transaction_input& ti);
  void read(std::istream& is, transaction_output& to);
  void write(std::ostream& os, const transaction_output& to);
}

#include "../utils/io.h"

namespace
{
  void read(std::istream& is, ecdsa_signature_t& sig)
  {
    read(is, sig.r);
    read(is, sig.s);
  }

  void write(std::ostream& os, const ecdsa_signature_t& sig)
  {
    write(os, sig.r);
    write(os, sig.s);
  }

  void read(std::istream& is, transaction_input& ti)
  {
    read(is, ti.transaction_hash);
    read(is, ti.output_index);
    read(is, ti.signature);
  }

  void write(std::ostream& os, const transaction_input& ti)
  {
    write(os, ti.transaction_hash);
    write(os, ti.output_index);
    write(os, ti.signature);
  }

  void read(std::istream& is, transaction_output& to)
  {
    read(is, to.target);
    read(is, to.amount);
  }

  void write(std::ostream& os, const transaction_output& to)
  {
    write(os, to.target);
    write(os, to.amount);
  }
}

void read(std::istream& is, ecc_public_key_t& pk)
{
  read(is, pk.x);
  read(is, pk.y);
  read(is, pk.identity);
}

void write(std::ostream& os, const ecc_public_key_t& pk)
{
  write(os, pk.x);
  write(os, pk.y);
  write(os, pk.identity);
}

void read(std::istream& is, transaction& t)
{
  read(is, t.inputs, true);
  read(is, t.outputs, true);
  read(is, t.timestamp);
}

void write(std::ostream& os, const transaction& t)
{
  write(os, t.inputs, true);
  write(os, t.outputs, true);
  write(os, t.timestamp);
}

void read(std::istream& is, block& b)
{
  read(is, b.previous);
  read(is, b.seed);
  read(is, b.root_hash);
}

void write(std::ostream& os, const block& b)
{
  write(os, b.previous);
  write(os, b.seed);
  write(os, b.root_hash);
}

void read(std::istream& is, full_block& b)
{
  read(is, b.block);
  read(is, b.transactions, true);
  read(is, b.reward);
}

void write(std::ostream& os, const full_block& b)
{
  write(os, b.block);
  write(os, b.transactions, true);
  write(os, b.reward);
}
