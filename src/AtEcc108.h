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
#ifndef LIB_ATECC108_H_
#define LIB_ATECC108_H_

#include "AtSha204.h"
#include "atecc108-atmel/ecc108_physical.h"

class AtEcc108 : public AtSha204
{
public:
  AtEcc108();
  ~AtEcc108();


  uint8_t wakeup();
  uint8_t getRandom(bool update_seed);
  uint8_t personalize();
  bool is_locked(const uint8_t ZONE);
  void burn_otp();
  uint8_t lock_data_zone();
  uint8_t sign(uint8_t *data, int len_32);



protected:
  const uint8_t ADDRESS;
  const uint8_t getAddress() const;
  const uint8_t write(uint8_t zone, uint16_t address, uint8_t *new_value,
                      uint8_t *mac, uint8_t size);
  void idle();
  void burn_config();
  uint8_t lock_config_zone();
  uint8_t read_config_zone(uint8_t *config_data);
  int load_nonce(uint8_t *to_load, int len);
  int sign_tempkey(const uint8_t KEY_ID);

  bool always_idle = true;
  bool always_wakeup = true;

  void disableIdleWake();
  void enableIdleWake();



};

#endif
