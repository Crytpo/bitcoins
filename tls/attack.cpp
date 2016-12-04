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

#include "attack.h"

#include <iostream>
#include "endian.h"
#include <algorithm>
#include <pthread.h>
#include <array>
#include <deque>

std::vector<uint8_t> lucky13_pe(const oracle::record& original_record, local_oracle& oracle)
{
    return std::vector<uint8_t>();
}

std::vector<uint8_t> lucky13_tsc(const oracle::record& original_record, local_oracle& oracle)
{
  std::cout << "Ciphertext Length: " << original_record.ciphertext.size() << std::endl;

  // No guarantee that TimeStampCounter synchronized between cores -> force everything to one core
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

  // definie blocksize and vector where the full plaintext will be saved into
  int blocksize = 16;
  std::deque<uint8_t> plaintext;

  // create vector with IV and ciphertext for easier copying (at least 2 * blocksize)
  std::vector<uint8_t> ciphertext(original_record.ciphertext.size() + sizeof(original_record.iv));
  std::copy(original_record.iv.begin(), original_record.iv.end(), ciphertext.begin());
  std::copy(original_record.ciphertext.begin(), original_record.ciphertext.end(), ciphertext.begin() + sizeof(original_record.iv));

  // create record that will be used for the attack
  oracle::record record_delta;
  record_delta.header = original_record.header;
  uint16_t header_length = 4 * blocksize + sizeof(record_delta.iv);
  record_delta.header.length = hton(header_length);
  record_delta.iv = original_record.iv;
  record_delta.ciphertext.resize(4 * blocksize, 0);

  // specify the number of times the same delta will be tested to be able to differentiate the cases
  // NOTE: 20 rounds also worked most of the times, but to be sure use 50 (could also use 2^7 according to paper)
  // NOTE: Timings on laptop more unreliable than on PC (did not test that stuff in the Newsgroup)
  int rounds = 50;

  // a few variables used for padding sanity check
  int padding = -1;
  bool padding_valid = true;
  int padding_tries = 3;
  int padding_bytes_left = -1;

  // Use last two blocks to recover last block according to paper and delete the recovered block -> IV left at the end
  while (ciphertext.size() != sizeof(record_delta.iv))
  {
    // padding sanity check - if padding not successfully recovered -> try again a max of 3 times, otherwise just continue
    if (padding_valid == false && padding_tries > 0)
    {
      std::cout << "ERROR: padding sanity check failed - Trying again." << std::endl;
      plaintext.clear();

      ciphertext = std::vector<uint8_t>(original_record.ciphertext.size() + sizeof(original_record.iv));
      std::copy(original_record.iv.begin(), original_record.iv.end(), ciphertext.begin());
      std::copy(original_record.ciphertext.begin(), original_record.ciphertext.end(), ciphertext.begin() + sizeof(original_record.iv));

      --padding_tries;
      padding_valid = true;
      padding = -1;
      padding_bytes_left = -1;
    }


    std::deque<uint8_t> plaintext_cur_block; // used for recovery of current last block

    { // first 2 bytes
      std::vector< std::vector<uint64_t> > timings; // matrix: rows determine delta, columns the round
      timings.resize(65536);

      // copy C3 and C4 (C1 = C2 = 0 and does not matter for the attack)
      std::copy(ciphertext.end() - (2 * blocksize), ciphertext.end(), record_delta.ciphertext.begin() + (2 * blocksize));

      // pointer to last two bytes and also save original value for resetting everything
      uint16_t* C3_last_bytes = reinterpret_cast<uint16_t*>(record_delta.ciphertext.data() + (3 * blocksize - 2));
      uint16_t orig_last_bytes = (*C3_last_bytes);

      // change bytes before such that xor with delta of 0 does not create a valid padding except if it actually is 0x01 | 0x01
      C3_last_bytes[-1] = C3_last_bytes[-1] ^ 0x123;

      for (int round = 0; round < rounds; ++round) // need multiple rounds to reliable differentiate the cases
      {
        for (int delta = 0; delta <= 65535; ++delta) // 65535 = 2^16 - 1 = max of 16 bits
        {
          // xor last two bytes of C3 with (combined) delta to change P4
          (*C3_last_bytes) = orig_last_bytes ^ static_cast<uint16_t>(delta);

          if (round == 0)
            timings[delta].resize(rounds);

          // save timing that decryption took with current delta
          timings[delta][round] = oracle.decrypt(record_delta).second;
        }
      }

      // according to paper, using the median of the calculated values should be good enough, especially since we do not have network noise
      // lowest median timing value corresponds with case 2 -> found delta
      uint64_t min_timing = timings[0][0];
      uint16_t min_delta = 0;

      for (int delta = 0; delta <= 65535; ++delta)
      {
        std::sort(timings[delta].begin(), timings[delta].end());

        if ((timings[delta][rounds/2]) < min_timing)
        {
          min_timing = timings[delta][rounds/2];
          min_delta = static_cast<uint16_t>(delta);
        }
      }

      // last 2 bytes = 0x01 XOR with the corresponding delta -> save it
      uint8_t* last_deltas = reinterpret_cast<uint8_t*>(&min_delta);
      plaintext_cur_block.push_front(0x01 ^ last_deltas[1]);
      plaintext_cur_block.push_front(0x01 ^ last_deltas[0]);

      // save padding for sanity check
      if (padding == -1)
      {
        padding = *plaintext_cur_block.rbegin();
        padding_bytes_left = padding + 1; // +1 because byte with padding value itself not included
        std::cout << "Padding: " << padding << std::endl;
      }
    }

    // recover other 14 bytes
    for (int current_byte = 2; current_byte < 16; ++current_byte)
    {
      std::vector< std::vector<uint64_t> > timings; // matrix: rows determine delta, columns the round
      timings.resize(256);

      // reset blocks
      std::copy(ciphertext.end() - (2 * blocksize), ciphertext.end(), record_delta.ciphertext.begin() + (2 * blocksize));

      // pointer to current byte that should be recovered and also save original value for resetting everything
      uint8_t* C3_current_byte = reinterpret_cast<uint8_t*>(record_delta.ciphertext.data() + (3 * blocksize - (current_byte + 1)));
      uint8_t orig_byte_value = (*C3_current_byte);

      // XOR previous bytes of ciphertext to get the needed pattern (e.g. 0x02 | 0x02 | 0x02)
      for (int prev_byte_index = 0; prev_byte_index < current_byte; ++prev_byte_index)
      {
        uint8_t* C3_previous_byte = reinterpret_cast<uint8_t*>(record_delta.ciphertext.data() + (3 * blocksize - (prev_byte_index + 1)));
        uint8_t delta_for_padding = (*(plaintext_cur_block.rbegin() + prev_byte_index)) ^ static_cast<uint8_t>(current_byte); // current_byte = needed padding value (e.g. 0x02)
        (*C3_previous_byte) = (*C3_previous_byte) ^ delta_for_padding;
      }

      for (int round = 0; round < rounds; ++round) // need multiple rounds to reliable differentiate the cases
      {
        // try every possible delta to get the correct padding in the plaintext P4
        for (int delta = 0; delta <= 255; ++delta) // 255 = 2^8 - 1 = max of 8 bits
        {
          // xor current byte of C3 with delta to change same byte in P4
          (*C3_current_byte) = orig_byte_value ^ static_cast<uint8_t>(delta);

          if (round == 0)
            timings[delta].resize(rounds);

          // save timing that decryption took with current delta
          timings[delta][round] = oracle.decrypt(record_delta).second;
        }
      }

      // lowest median timing value corresponds with case 2 -> found delta
      uint64_t min_timing = timings[0][0];
      uint8_t min_delta = 0;

      for (int delta = 0; delta <= 255; ++delta)
      {
        std::sort(timings[delta].begin(), timings[delta].end());

        if ((timings[delta][rounds/2]) < min_timing)
        {
          min_timing = timings[delta][rounds/2];
          min_delta = static_cast<uint8_t>(delta);
        }
      }

      // Recovered byte = Padding XOR with the found delta -> save it
      plaintext_cur_block.push_front(current_byte ^ min_delta); // current_byte = needed padding value (e.g. 0x02)
    }

    // Padding Sanity Check after every block, if full padding has not yet been checked
    // if block contains padding -> check if correct (from back to front)
    if (padding_bytes_left > 0)
    {
      std::deque<uint8_t>::reverse_iterator block_iterator = plaintext_cur_block.rbegin();

      while (padding_bytes_left > 0 && block_iterator != plaintext_cur_block.rend())
      {
        if (*block_iterator != padding)
        {
          padding_valid = false;
          padding_bytes_left = -1;
          break;
        }

        block_iterator++;
        --padding_bytes_left;
      }
    }

    // add recovered block to all recovered blocks
    plaintext.insert(plaintext.begin(), plaintext_cur_block.begin(), plaintext_cur_block.end());

    // remove the recovered block
    ciphertext.erase(ciphertext.end() - blocksize, ciphertext.end());
  }

  // calculate the size of the plaintext (ALL - HMAC - Padding - 1)
  int plaintext_length = original_record.ciphertext.size() - 20 - padding - 1;// 20 = HMAC, x + 1 = padding
  std::cout << "Plaintext Length: ciphertext(" << original_record.ciphertext.size()
            << ") - HMAC(20) - PaddingLength(" << padding << ") - PaddingValue(1)"
            << " = " << plaintext_length << std::endl;

  // extract only the plaintext (OP) and return it
  std::vector<uint8_t> recovered_plaintext(plaintext.begin(), plaintext.begin() + plaintext_length);
  std::cout << std::endl << "Recovered plaintext = \"";
  for (uint8_t character : recovered_plaintext)
  {
    std::cout << character;
  }
  std::cout << "\"" << std::endl << std::endl;

  return std::vector<uint8_t>(plaintext.begin(), plaintext.begin() + plaintext_length);
}

std::vector<uint8_t> lucky13_tsc(const oracle::record& original_record, remote_oracle& oracle)
{
  std::cout << "LENGTH: " << original_record.ciphertext.size() << std::endl;

  return std::vector<uint8_t>();
}
