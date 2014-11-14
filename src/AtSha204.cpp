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

AtSha204::AtSha204(const uint8_t addr) : address(addr)
{

}


AtSha204::~AtSha204() { }
