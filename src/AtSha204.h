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
#ifndef LIB_ATSHA204_H_
#define LIB_ATSHA204_H_

#include <Arduino.h>
#include <CryptoBuffer.h>

class AtSha204
{
public:
  AtSha204();
  ~AtSha204();

  CryptoBuffer rsp;
  uint8_t getRandom();

protected:
  static uint8_t command[SHA204_CMD_SIZE_MAX];
  static uint8_t temp[RANDOM_RSP_SIZE];

};



#endif
