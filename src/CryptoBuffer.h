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
#ifndef LIB_CRYPTOBUFFER_H_
#define LIB_CRYPTOBUFFER_H_

#include <Arduino.h>
#include <atsha204-atmel/sha204_comm_marshaling.h>


class CryptoBuffer
{
 public:
    CryptoBuffer();
    ~CryptoBuffer();

    const uint8_t *getPointer();
    const int getMaxBufferSize();
    const int getLength();
    void copyBufferFrom(uint8_t *src, int len);

 protected:
    int len;

    uint8_t buf[SHA204_RSP_SIZE_MAX];
    void clear();


};



#endif