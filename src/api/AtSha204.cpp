/* -*- mode: c++; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of cryptoauth-arduino.
 *
 * cryptoauth-arduino is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * cryptoauth-arduino is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cryptoauth-arduino.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "AtSha204.h"
#include "../atsha204-atmel/sha204_physical.h"
#include "../atsha204-atmel/sha204_comm_marshaling.h"
#include "../atsha204-atmel/sha204_lib_return_codes.h"

AtSha204::AtSha204()
{
  sha204p_init();
}


AtSha204::~AtSha204() { }

void AtSha204::idle()
{
    sha204p_idle();
}

uint8_t AtSha204::getRandom()
{
  volatile uint8_t ret_code;

  uint8_t *random = &this->temp[SHA204_BUFFER_POS_DATA];

  sha204p_wakeup();

  ret_code = sha204m_random(this->command, this->temp, RANDOM_NO_SEED_UPDATE);
  if (ret_code == SHA204_SUCCESS)
    {
      this->rsp.copyBufferFrom(random, 32);
    }


  sha204p_idle();
  return ret_code;
}


void AtSha204::enableDebug(Stream* stream)
{
  this->debugStream = stream;
}


uint8_t AtSha204::macBasic(uint8_t *to_mac, int len)
{
  uint16_t key_id = 0;
  uint8_t mode = MAC_MODE_CHALLENGE;
  uint8_t rc;

  if (MAC_CHALLENGE_SIZE != len)
    return SHA204_BAD_PARAM;

  sha204p_wakeup();

  if (SHA204_SUCCESS ==
      (rc = sha204m_mac(this->command, this->temp, mode, key_id, to_mac)))
    {
      this->rsp.copyBufferFrom(&this->temp[SHA204_BUFFER_POS_DATA], 32);
    }

  sha204p_idle();
  return rc;

}

uint8_t AtSha204::checkMacBasic(uint8_t *to_mac, int len, uint8_t *rsp)
{
  uint16_t key_id = 0;
  uint8_t mode = MAC_MODE_CHALLENGE;
  uint8_t other_data[13] = {0};
  uint8_t rc;

  if (MAC_CHALLENGE_SIZE != len)
    return SHA204_BAD_PARAM;

  other_data[0] = 0x08;
  sha204p_wakeup();

  rc = sha204m_check_mac(this->command, this->temp,
                         mode, key_id, to_mac, rsp, other_data);

  sha204p_idle();
  return rc;

}


uint8_t AtSha204::checkResponseStatus(uint8_t ret_code, uint8_t *response) const
{
  if (ret_code != SHA204_SUCCESS)
    {
      return ret_code;
    }

  ret_code = response[SHA204_BUFFER_POS_STATUS];

  return ret_code;
}

#define rotate_right(value, places) ((value >> places) | (value << (32 - places)))
#define SHA256_BLOCK_SIZE   (64)   // bytes

/** \brief This function creates a SHA256 digest on a little-endian system.
 *
 * Limitations: This function was implemented with the ATSHA204 CryptoAuth device
 * in mind. It will therefore only work for length values of len % 64 < 62.
 *
 * \param[in] len byte length of message
 * \param[in] message pointer to message
 * \param[out] digest SHA256 of message

 * TODO: Replace with ATSHA204 implementation
 */
void AtSha204::calculate_sha256(int32_t len, uint8_t *message, uint8_t *digest)
{
  int32_t j, swap_counter, len_mod = len % sizeof(int32_t);
  uint32_t i, w_index;
  int32_t message_index = 0;
  uint32_t padded_len = len + 8; // 8 bytes for bit length
  uint32_t bit_len = len * 8;
  uint32_t s0, s1;
  uint32_t t1, t2;
  uint32_t maj, ch;
  uint32_t word_value;
  uint32_t rotate_register[8];

  union {
    uint32_t w_word[SHA256_BLOCK_SIZE];
    uint8_t w_byte[SHA256_BLOCK_SIZE * sizeof(int32_t)];
  } w_union;

  uint32_t hash[] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  };

  const uint32_t k[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  };

  // Process message.
  while (message_index <= padded_len) {

    // Break message into 64-byte blocks.
    w_index = 0;
    do {
      // Copy message chunk of four bytes (size of integer) into compression array.
      if (message_index < (len - len_mod)) {
        for (swap_counter = sizeof(int32_t) - 1; swap_counter >= 0; swap_counter--)
          // No padding needed. Swap four message bytes to chunk array.
          w_union.w_byte[swap_counter + w_index] = message[message_index++];

        w_index += sizeof(int32_t);
      }
      else {
        // We reached last complete word of message {len - (len mod 4)}.
        // Swap remaining bytes if any, append '1' bit and pad remaining
        // bytes of the last word.
        for (swap_counter = sizeof(int32_t) - 1;
            swap_counter >= sizeof(int32_t) - len_mod; swap_counter--)
          w_union.w_byte[swap_counter + w_index] = message[message_index++];
        w_union.w_byte[swap_counter + w_index] = 0x80;
        for (swap_counter--; swap_counter >= 0; swap_counter--)
          w_union.w_byte[swap_counter + w_index] = 0;

        // Switch to word indexing.
        w_index += sizeof(int32_t);
        w_index /= sizeof(int32_t);

        // Pad last block with zeros to a block length % 56 = 0
        // and pad the four high bytes of "len" since we work only
        // with integers and not with long integers.
        while (w_index < 15)
           w_union.w_word[w_index++] = 0;
        // Append original message length as 32-bit integer.
        w_union.w_word[w_index] = bit_len;
        // Indicate that the last block is being processed.
        message_index += SHA256_BLOCK_SIZE;
        // We are done with pre-processing last block.
        break;
      }
    } while (message_index % SHA256_BLOCK_SIZE);
    // Created one block.

    w_index = 16;
    while (w_index < SHA256_BLOCK_SIZE) {
      // right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
      word_value = w_union.w_word[w_index - 15];
      s0 = rotate_right(word_value, 7) ^ rotate_right(word_value, 18) ^ (word_value >> 3);

      word_value = w_union.w_word[w_index - 2];
      s1 = rotate_right(word_value, 17) ^ rotate_right(word_value, 19) ^ (word_value >> 10);

      w_union.w_word[w_index] = w_union.w_word[w_index - 16] + s0 + w_union.w_word[w_index - 7] + s1;

      w_index++;
    }

    // Initialize hash value for this chunk.
    for (i = 0; i < 8; i++)
      rotate_register[i] = hash[i];

    // hash calculation loop
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
      s0 = rotate_right(rotate_register[0], 2)
        ^ rotate_right(rotate_register[0], 13)
        ^ rotate_right(rotate_register[0], 22);
      maj = (rotate_register[0] & rotate_register[1])
        ^ (rotate_register[0] & rotate_register[2])
        ^ (rotate_register[1] & rotate_register[2]);
      t2 = s0 + maj;
      s1 = rotate_right(rotate_register[4], 6)
        ^ rotate_right(rotate_register[4], 11)
        ^ rotate_right(rotate_register[4], 25);
      ch =  (rotate_register[4] & rotate_register[5])
        ^ (~rotate_register[4] & rotate_register[6]);
      t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

      rotate_register[7] = rotate_register[6];
      rotate_register[6] = rotate_register[5];
      rotate_register[5] = rotate_register[4];
      rotate_register[4] = rotate_register[3] + t1;
      rotate_register[3] = rotate_register[2];
      rotate_register[2] = rotate_register[1];
      rotate_register[1] = rotate_register[0];
      rotate_register[0] = t1 + t2;
    }

      // Add the hash of this block to current result.
    for (i = 0; i < 8; i++)
      hash[i] += rotate_register[i];
  }

  // All blocks have been processed.
  // Concatenate the hashes to produce digest, MSB of every hash first.
  for (i = 0; i < 8; i++) {
    for (j = sizeof(int32_t) - 1; j >= 0; j--, hash[i] >>= 8)
      digest[i * sizeof(int32_t) + j] = hash[i] & 0xFF;
  }

}

