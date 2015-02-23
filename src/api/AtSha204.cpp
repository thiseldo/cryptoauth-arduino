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
