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
#include <CryptoBuffer.h>

CryptoBuffer::CryptoBuffer()
{
    this->clear();
    this->len = 0;
}

CryptoBuffer::~CryptoBuffer() { }

void CryptoBuffer::clear()
{
    memset(&this->buf[0], 0, this->getMaxBufferSize());
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
    return SHA204_RSP_SIZE_MAX;
}

void CryptoBuffer::copyBufferFrom(uint8_t *src, int len)
{
    if (len <= this->getMaxBufferSize())
        {
            memcpy (this->buf, src, len);
            this->len = len;
        }
}
