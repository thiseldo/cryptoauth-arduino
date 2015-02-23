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
#include "CryptoBuffer.h"
#include <stdio.h>

CryptoBuffer::CryptoBuffer()
{
    this->clear();
}

CryptoBuffer::~CryptoBuffer() { }

void CryptoBuffer::clear()
{
    memset(&this->buf[0], 0, this->getMaxBufferSize());
    this->len = 0;
}

const int CryptoBuffer::getLength()
{
    return this->len;
}

const uint8_t *CryptoBuffer::getPointer()
{
    return this->buf;
}

const int CryptoBuffer::getMaxBufferSize()
{
  return sizeof(this->buf);
}

void CryptoBuffer::copyBufferFrom(uint8_t *src, int len)
{
    if (len <= this->getMaxBufferSize())
        {
            memcpy (this->buf, src, len);
            this->len = len;
        }
}

const void CryptoBuffer::dumpHex(Stream* stream)
{
  char temp[3] = {};
  for (int x = 0; x < this->getLength(); x++){
    sprintf(temp, "%02x",this->getPointer()[x]);
    stream->print(temp);
  }

  stream->write("\n");
}
