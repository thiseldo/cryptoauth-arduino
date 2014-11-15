/* -*- mode: c++; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of atsha204-arduino.
 *
 * atsha204-arduino is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * atsha204-arduino is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with atsha204-arduino.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <AtSha204.h>
#include <atsha204-atmel/sha204_physical.h>
#include <atsha204-atmel/sha204_comm_marshaling.h>
#include <atsha204-atmel/sha204_lib_return_codes.h>

AtSha204::AtSha204()
{
  sha204p_init();
}


AtSha204::~AtSha204() { }

uint8_t AtSha204::getRandom()
{
  volatile uint8_t ret_code;

  uint8_t *random = &this->temp[SHA204_BUFFER_POS_DATA];

  ret_code = sha204m_random(this->command, this->temp, RANDOM_NO_SEED_UPDATE);
  if (ret_code == SHA204_SUCCESS)
    {
      this->rsp.copyBufferFrom(random, 32);
    }


  sha204p_idle();
  return ret_code;
}
