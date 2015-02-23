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
#ifndef LIB_CRYPTOBUFFER_H_
#define LIB_CRYPTOBUFFER_H_

#include <Arduino.h>
#include "../atecc108-atmel/ecc108_physical.h"
class CryptoBuffer
{
public:
  CryptoBuffer();
  ~CryptoBuffer();

  const uint8_t *getPointer();
  const int getMaxBufferSize();
  const int getLength();
  void copyBufferFrom(uint8_t *src, int len);
  const void dumpHex(Stream* stream);
  void clear();

protected:
  int len;

  uint8_t buf[ECC108_RSP_SIZE_MAX];

};



#endif
