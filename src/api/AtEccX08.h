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
#ifndef LIB_ATECCX08_H_
#define LIB_ATECCX08_H_

#include "AtSha204.h"
#include "../ateccX08-atmel/eccX08_physical.h"

class AtEccX08 : public AtSha204
{
public:
  AtEccX08();
  ~AtEccX08();


  uint8_t wakeup();
  uint8_t getRandom(bool update_seed = false);
  uint8_t personalize(const uint8_t * config_zone_data, uint8_t config_len,
                      const uint8_t * otp_zone_data, uint8_t optlen);
  bool is_locked(const uint8_t ZONE);
  void burn_otp();
  uint8_t lock_data_zone();
  uint8_t lockKeySlot( uint8_t slotNum );
  uint8_t sign(uint8_t key, uint8_t *data, int len_32);
  uint8_t verify(uint8_t *data, int len_32,
                 uint8_t *pub_key,
                 uint8_t *signature);
  uint8_t hash_verify(const uint8_t *data, int len,
                 uint8_t *pub_key,
                 uint8_t *signature);
//  uint8_t getPubKey(const uint8_t KEY_ID);
//  uint8_t genPrivateKey(const uint8_t KEY_ID);
  uint8_t genEccKey(const uint8_t KEY_ID, bool privateKey);
  uint8_t getSerialNumber(void);
  uint8_t getInfo(uint8_t info, uint16_t key_id);
  uint8_t getKeySlotConfig(void);
  uint8_t calculateSHA256( uint8_t *data, int len);   //, uint8_t *outBuf );


protected:
  const uint8_t ADDRESS;
  const uint8_t getAddress() const;
  const uint8_t write(uint8_t zone, uint16_t address, uint8_t *new_value,
                      uint8_t *mac, uint8_t size);
  void idle();
  void burn_config(const uint8_t * data,uint8_t datalen);
  void burn_otp(const uint8_t * data,uint8_t datalen);

  uint8_t lock_config_zone();
  uint8_t read_config_zone(uint8_t *config_data);
  int load_nonce(uint8_t *to_load, int len);
  int sign_tempkey(const uint8_t KEY_ID);
  uint8_t verify_tempkey( //const uint8_t KEY_ID,
                         uint8_t *pub_key,
                         uint8_t *signature);

  bool always_idle = true;
  bool always_wakeup = true;

  void disableIdleWake();
  void enableIdleWake();

};

#endif
