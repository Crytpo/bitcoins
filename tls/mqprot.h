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

#ifndef MQPROT_H
#define MQPROT_H

#include "tls-aes-cbc-hmac-sha1.h"

enum command : uint8_t
{
  // request the original ciphertext
  REQUEST_CIPHERTEXT,
  // request ciphertext of a given size
  REQUEST_CHALLENGE,
  // send challenge to be decrypted
  SEND_CHALLENGE,
  // quit
  QUIT
};

enum mq_status : uint8_t
{
  OK,
  DEC_FAILED,
  UNKNOWN_ERROR
};

union control_message {
  struct
  {
    command cmd;
  };

  struct
  {
    command cmd;
  } quit;

  struct
  {
    command cmd;
    uint16_t challenge_size;
  } request_challenge;

  struct
  {
    command cmd;
  } request_ciphertext;

  struct
  {
    command cmd;
    uint16_t size;
    record_layer_header header;
    tls12_aes_cbc_hmac_sha1::initialization_vector iv;
    uint16_t ciphertext_size;
    std::array<uint8_t, 1 << 14> ciphertext;
  } send_challenge;
} __attribute__((packed));

union result_message {
  struct
  {
    mq_status status;
  };

  struct
  {
    mq_status status;

    record_layer_header header;
    tls12_aes_cbc_hmac_sha1::initialization_vector iv;
    uint16_t data_size;
    std::array<uint8_t, 1 << 14> data;
  } ciphertext;

  struct
  {
    mq_status status;

    uint64_t timing;
    uint16_t data_size;
    std::array<uint8_t, 1 << 14> data;
  } plaintext;
};

#endif
