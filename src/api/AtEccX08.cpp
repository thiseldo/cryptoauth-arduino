/* -*- mode: c++; c-file-style: "gnu" -*- Copyright (C) 2014
 * Cryptotronix, LLC.
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
#include "AtEccX08.h"
#include "../ateccX08-atmel/eccX08_physical.h"
#include "../ateccX08-atmel/eccX08_comm_marshaling.h"
#include "../ateccX08-atmel/eccX08_lib_return_codes.h"
#include "../softcrypto/sha256.h"

// Make these external to the library - need to be passed via personalisation sketch
/*
static const uint8_t default_config_zone[] =
  {
    0x01, 0x23, 0x53, 0x64, 0x80, 0x00, 0x10, 0x01, 0x51, 0x2A, 0xCB,
    0x1C, 0xEE, 0xC0, 0xA7, 0x00, 0xC0, 0x00, 0xAA, 0x00, 0x81, 0xA0,
    0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0, 0x81,
    0xA0, 0x81, 0xA0, 0x00, 0x00, 0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0,
    0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0, 0x81, 0xA0, 0xFF, 0x00, 0xFF,
    0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,
    0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x09, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x33,
    0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00,
    0x3C, 0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00, 0x33,
    0x00, 0x33, 0x00, 0x33, 0x00, 0x33, 0x00
  };

// Make these external to the library - need to be passed via personalisation sketch
// convert to ascii to see what this says - put customised message
static const uint8_t otp_zone[] =
  {
    0x43, 0x52, 0x59, 0x50, 0x54, 0x52, 0x4f, 0x4e, 0x49, 0x58, 0x20,
    0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x41, 0x55, 0x54, 0x48, 0x20,
    0x41, 0x52, 0x44, 0x55, 0x49, 0x4e, 0x4f, 0x20, 0x53, 0x4f, 0x46,
    0x54, 0x57, 0x41, 0x52, 0x45, 0x20, 0x56, 0x45, 0x52, 0x53, 0x49,
    0x4f, 0x4e, 0x3a, 0x20, 0x30, 0x2e, 0x31, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
*/

AtEccX08::AtEccX08() : ADDRESS(0xC0)
{
    eccX08p_init();
}



AtEccX08::~AtEccX08() { }

void AtEccX08::idle()
{
  if (this->always_idle)
    eccX08p_idle();
}

uint8_t AtEccX08::wakeup()
{
  if (!this->always_wakeup)
    return 0;

  uint8_t wakeup_response[ECCX08_RSP_SIZE_MIN];

  memset(wakeup_response, 0, sizeof(wakeup_response));
  return eccX08c_wakeup(wakeup_response);
}

const uint8_t AtEccX08::getAddress() const
{
    return this->ADDRESS;
}

uint8_t AtEccX08::getRandom(bool update_seed)
{
    volatile uint8_t ret_code;

    uint8_t *random = &this->temp[ECCX08_BUFFER_POS_DATA];

    //ret_code = ecc108m_random(this->command, this->temp,
    //RANDOM_NO_SEED_UPDATE);
    uint8_t SEED_UPDATE;

    if (update_seed)
      SEED_UPDATE = RANDOM_SEED_UPDATE;
    else
      SEED_UPDATE = RANDOM_NO_SEED_UPDATE;

    this->rsp.clear();
    this->wakeup();

    ret_code = eccX08m_execute(ECCX08_RANDOM, SEED_UPDATE, 0x0000,
		    0, NULL, 0, NULL, 0, NULL,
		    sizeof(this->command), this->command,
		    sizeof(this->temp), this->temp);

    if (ret_code == ECCX08_SUCCESS)
    {
        this->rsp.copyBufferFrom(random, 32);
    }


    this->idle();
    return ret_code;
}


const uint8_t AtEccX08::write(uint8_t zone, uint16_t address, uint8_t *new_value,
                              uint8_t *mac, uint8_t size)
{

  if ( !new_value || (zone & ~WRITE_ZONE_MASK))
    // no null pointers allowed
    // zone has to match a valid param1 value.
    return ECCX08_BAD_PARAM;

  address >>= 2;
  if ((zone & ECCX08_ZONE_MASK) == ECCX08_ZONE_CONFIG)
    {
      if (address > ECCX08_ADDRESS_MASK_CONFIG)
        return ECCX08_BAD_PARAM;
    }
  else if ((zone & ECCX08_ZONE_MASK) == ECCX08_ZONE_OTP)
    {
      if (address > ECCX08_ADDRESS_MASK_OTP)
        return ECCX08_BAD_PARAM;
    }
  else if ((zone & ECCX08_ZONE_MASK) == ECCX08_ZONE_DATA)
    {
      if (address > ECCX08_ADDRESS_MASK)
        return ECCX08_BAD_PARAM;
    }

  if (ECCX08_ZONE_ACCESS_32 != size && ECCX08_ZONE_ACCESS_4 != size)
    {
      return ECCX08_BAD_PARAM;
    }

  uint8_t param1 = zone;
  uint16_t param2 = (uint8_t) (address & ECCX08_ADDRESS_MASK);
  //*p_command++ = 0;

  // count = (zone & ECCX08_ZONE_COUNT_FLAG) ?
  //   ECCX08_ZONE_ACCESS_32 : ECCX08_ZONE_ACCESS_4;

  // if (mac != NULL)
  //   {
  //     memcpy(p_command, mac, WRITE_MAC_SIZE);
  //     p_command += WRITE_MAC_SIZE;
  //   }

  return  eccX08m_execute(ECCX08_WRITE, param1, param2,
			  size, new_value, 0, NULL, 0, NULL,
			  sizeof(this->command), this->command,
               		  sizeof(this->temp), this->temp);

}

// Pass config
// Skip first 16 bytes as not writeable
void AtEccX08::burn_config(const uint8_t * data, uint8_t datalen )
  {
 //   const uint8_t * data = default_config_zone;

    this->rsp.clear();

    for (int x = 0; x < datalen; x+=ECCX08_ZONE_ACCESS_4)
      {
        this->wakeup();
        this->write(ECCX08_ZONE_CONFIG, 16+x, const_cast<uint8_t *>(data+x), NULL,
                    ECCX08_ZONE_ACCESS_4);
        this->idle();
      }

  }

void AtEccX08::burn_otp(const uint8_t * data, uint8_t datalen)
{
//  const uint8_t * data = otp_zone;

  this->rsp.clear();

  for (int x = 0; x < datalen; x+=ECCX08_ZONE_ACCESS_32)
    {
      this->wakeup();
      this->write(ECCX08_ZONE_OTP, x, const_cast<uint8_t *>(data+x), NULL,
                  ECCX08_ZONE_ACCESS_32);
      this->idle();
    }

}

uint8_t AtEccX08::lock_config_zone()
{
  uint8_t ret_code;
  uint8_t crc_array[ECCX08_CRC_SIZE];
  uint16_t crc;
  uint8_t config_data[ECCX08_CONFIG_SIZE];


  ret_code = this->read_config_zone(config_data);
  if (ret_code != ECCX08_SUCCESS)
    {
      return ret_code;
    }

  eccX08c_calculate_crc(sizeof(config_data),
                        config_data,
                        crc_array);
  crc = (crc_array[1] << 8) + crc_array[0];

  this->wakeup();
  ret_code = eccX08m_execute(ECCX08_LOCK, ECCX08_ZONE_CONFIG, crc,
                             0, NULL, 0, NULL, 0, NULL,
                             sizeof(this->command), this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}

uint8_t AtEccX08::lock_data_zone()
{
  uint8_t ret_code;
//  uint8_t crc_array[ECCX08_CRC_SIZE];
//  uint16_t crc;
//  uint8_t config_data[ECCX08_CONFIG_SIZE];

  this->wakeup();
  ret_code = eccX08m_execute(ECCX08_LOCK,
                             LOCK_ZONE_NO_CONFIG | LOCK_ZONE_NO_CRC, 0,
                             0, NULL, 0, NULL, 0, NULL,
                             sizeof(this->command), this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}


// Gets D2 - Parse error
uint8_t AtEccX08::lockKeySlot( uint8_t slotNum )
{
  uint8_t ret_code;
//  uint8_t crc_array[ECCX08_CRC_SIZE];
//  uint16_t crc;
//  uint8_t config_data[ECCX08_CONFIG_SIZE];

  this->wakeup();
  ret_code = eccX08m_execute(ECCX08_LOCK,
                             //LOCK_ZONE_NO_CONFIG | 
                             LOCK_MODE_SINGLE_SLOT | 
                             ((slotNum & 0x0f) << 2) | LOCK_ZONE_NO_CRC, 0,
                             0, NULL, 0, NULL, 0, NULL,
                             sizeof(this->command), this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}


// TODO: Use config from flash
uint8_t AtEccX08::personalize(const uint8_t * config_zone_data, uint8_t configlen,const uint8_t * otp_zone_data, uint8_t otplen) 
{
  bool config_locked;
  bool data_locked;

  config_locked = this->is_locked(0);
  data_locked = this->is_locked(1);

  if (!config_locked)
    {
      this->burn_config(config_zone_data,configlen);
      this->lock_config_zone();
    }

  if (!data_locked)
    {
      this->burn_otp(otp_zone_data,otplen);
      this->lock_data_zone();
    }

  return 0;
}


uint8_t AtEccX08::read_config_zone(uint8_t *config_data)
{
  // declared as "volatile" for easier debugging
  volatile uint8_t ret_code;

  uint16_t config_address;

  // Make the command buffer the size of the Read command.
  uint8_t command[READ_COUNT];

  // Make the response buffer the size of the maximum Read response.
  uint8_t response[READ_32_RSP_SIZE];

  // Read first 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
  ret_code = eccX08c_wakeup(response);
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  memset(response, 0, sizeof(response));
  config_address = 0;
  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  eccX08p_sleep();
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECCX08_BUFFER_POS_DATA],
           ECCX08_ZONE_ACCESS_32);
    config_data += ECCX08_ZONE_ACCESS_32;
  }

  // Read second 32 bytes.
  memset(response, 0, sizeof(response));
  ret_code = eccX08c_wakeup(response);
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  config_address += ECCX08_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  eccX08p_sleep();
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECCX08_BUFFER_POS_DATA], ECCX08_ZONE_ACCESS_32);
    config_data += ECCX08_ZONE_ACCESS_32;
  }

  // Read third 32 bytes.
  memset(response, 0, sizeof(response));
  ret_code = eccX08c_wakeup(response);
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  config_address += ECCX08_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  eccX08p_sleep();
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECCX08_BUFFER_POS_DATA], ECCX08_ZONE_ACCESS_32);
    config_data += ECCX08_ZONE_ACCESS_32;
  }

  // Read foruth 32 bytes.

  memset(response, 0, sizeof(response));
  ret_code = eccX08c_wakeup(response);
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  config_address += ECCX08_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  eccX08p_sleep();
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECCX08_BUFFER_POS_DATA], ECCX08_ZONE_ACCESS_32);
    config_data += ECCX08_ZONE_ACCESS_32;
  }


  eccX08p_sleep();

  if (ret_code == ECCX08_SUCCESS && config_data) {
    memcpy(config_data, &response[ECCX08_BUFFER_POS_DATA],
           ECCX08_ZONE_ACCESS_32);
  }

  return ret_code;
}

bool AtEccX08::is_locked(const uint8_t ZONE)
{

  uint16_t config_address = ECCX08_ZONE_ACCESS_32 * 2;
  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];
  /* Offset to lock byte */
  uint8_t offset = 22;
  bool status = false;
  uint8_t ret_code;

  this->rsp.clear();

  ret_code = this->wakeup();
  if (ret_code != ECCX08_SUCCESS)
    return false;

  this->rsp.clear();

  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(this->command),
                             this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  if (ret_code != ECCX08_SUCCESS)
    return false;

  if (ZONE == ECCX08_ZONE_CONFIG)
    {
      /* config zone is at offset 23 */
      offset++;
    }

  if (0 == *(rsp_ptr + offset))
    status = true;

  return status;
}

int AtEccX08::load_nonce(uint8_t *to_load, int len)
{
  // Pass the message to be signed using Nonce command with mode =
  // 0x03.
  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  this->wakeup();

  int ret_code =
    eccX08m_execute(ECCX08_NONCE,
                    NONCE_MODE_PASSTHROUGH,
                    NONCE_ZERO_RANDOM_OUT,
                    NONCE_NUMIN_SIZE_PASSTHROUGH,
                    to_load,
                    0, NULL, 0, NULL,
                    sizeof(this->command), this->command,
                    sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}

int AtEccX08::sign_tempkey(const uint8_t KEY_ID)
{
  this->rsp.clear();

  this->wakeup();

  int ret_code =
    eccX08m_execute(ECCX08_SIGN,
                    SIGN_MODE_EXTERNAL,
                    KEY_ID,
                    0, NULL, 0, NULL, 0, NULL,
                    sizeof(this->command), this->command,
                    sizeof(this->temp), this->temp);

  this->idle();

//  debugStream->print("sign_tempkey: ");
//  debugStream->println( ret_code, HEX);

  return ret_code;

}


uint8_t AtEccX08::sign(uint8_t key, uint8_t *data, int len_32)
{
  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  int ret_code = this->getRandom(true);

  if (ECCX08_SUCCESS == ret_code)
    {
      if ((ret_code = this->load_nonce(data, len_32)) == ECCX08_SUCCESS)
        {
          if ((ret_code = this->sign_tempkey(key)) == ECCX08_SUCCESS)
            {
              this->rsp.copyBufferFrom(rsp_ptr, VERIFY_256_SIGNATURE_SIZE);
            }
        }
    }

  return ret_code;


}

/** 
 *
 *
 */
uint8_t AtEccX08::genEccKey(const uint8_t KEY_ID, bool privateKey)
{
  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  this->wakeup();

  int ret_code =
    eccX08m_execute(ECCX08_GENKEY, privateKey ? GENKEY_MODE_PRIVATE : GENKEY_MODE_PUBLIC,
                    KEY_ID, 0, NULL, 0, NULL, 0, NULL,
                    sizeof(this->command), this->command,
                    sizeof(this->temp), this->temp);

  if (0 == ret_code)
    this->rsp.copyBufferFrom(rsp_ptr, VERIFY_256_KEY_SIZE);

//  debugStream->print("genPrivateKey: ");
//  debugStream->println( ret_code, HEX);

  return ret_code;
}
/*
uint8_t AtEccX08::getPubKey(const uint8_t KEY_ID)
{
  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  this->wakeup();

  int ret_code =
    eccX08m_execute(ECCX08_GENKEY, GENKEY_MODE_PUBLIC,
                    KEY_ID, 0, NULL, 0, NULL, 0, NULL,
                    sizeof(this->command), this->command,
                    sizeof(this->temp), this->temp);

  if (0 == ret_code)
    this->rsp.copyBufferFrom(rsp_ptr, VERIFY_256_KEY_SIZE);

  debugStream->print("getPubKey: ");
  debugStream->println( ret_code, HEX);

  return ret_code;
}
*/
uint8_t AtEccX08::verify_tempkey( uint8_t *pub_key,
                                 uint8_t *signature)
{
  this->rsp.clear();

  this->wakeup();

  int ret_code =
    eccX08m_execute(ECCX08_VERIFY, VERIFY_MODE_EXTERNAL,
                    VERIFY_KEY_P256, VERIFY_256_SIGNATURE_SIZE,
                    signature,
                    VERIFY_256_KEY_SIZE,
                    pub_key, 0, NULL,
                    sizeof(this->command), command,
                    sizeof(this->temp),
                    this->temp);

  if (0 == ret_code)
    {
      ret_code = this->temp[ECCX08_BUFFER_POS_DATA];
    }


  this->idle();

  return ret_code;

}

uint8_t AtEccX08::verify(uint8_t *data, int len_32,
                         uint8_t *pub_key,
                         uint8_t *signature)
{
  int ret_code = -1;

  if ((ret_code = this->load_nonce(data, len_32)) == ECCX08_SUCCESS)
    {
      ret_code = this->verify_tempkey( pub_key, signature);
    }
//  else
//    Serial.print("\nNonce failed to Loaded");

  return ret_code;
}

// This doesnt generate correct SHA256 HAsh
uint8_t
AtEccX08::hash_verify(const uint8_t *data, int len, uint8_t *pub_key,
                      uint8_t *signature)
{

  sha256_hash_t digest;
  sha256(&digest, data, len);

  Serial.write("\n");
  for (int i = 0; i < len; i++)
    {
      static char tmp[4] = {};
      if (i > 0)
        Serial.write(" ");

      sprintf(tmp, "0x%02X", digest[i]);
      Serial.write(tmp);
    }

  Serial.write("\n");


  return this->verify (&digest[0], sizeof(digest), pub_key, signature);

}



void AtEccX08::disableIdleWake()
{
  this->always_idle = false;
  this->always_wakeup = false;
}

void AtEccX08::enableIdleWake()
{
  this->always_idle = true;
  this->always_wakeup = true;
}


uint8_t AtEccX08::getSerialNumber(void)
{

  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  uint8_t ret_code = this->wakeup();

  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  memset(this->temp, 0, sizeof(this->temp));

  uint8_t config_address = 0;

  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(this->command),
                             this->command,
                             sizeof(this->temp), this->temp);


  const uint8_t SERIAL_NUM_LENGTH = 9;

  if (0 == ret_code) {
    //this->rsp.copyBufferFrom(rsp_ptr, READ_32_RSP_SIZE);  // VERIFY_256_KEY_SIZE);  // READ_32_RSP_SIZE
    uint8_t tmpSn[9];
    memcpy(tmpSn, &rsp_ptr[0], 4);
    memcpy(tmpSn + 4, &rsp_ptr[8], 5);
    this->rsp.copyBufferFrom(tmpSn, 9);
  }


  this->idle();

  return ret_code;
}


uint8_t AtEccX08::getInfo(uint8_t info, uint16_t key_id)
{

  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  uint8_t ret_code = this->wakeup();

  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  memset(this->temp, 0, sizeof(this->temp));

  ret_code = eccX08m_execute(ECCX08_INFO,
                             info,    //INFO_MODE_REVISION ,     // Param1, 8 bits
                             key_id,    //0,                       // Param2, 16 bits
                             0, NULL, 0, NULL, 0, NULL, sizeof(this->command),
                             this->command,
                             sizeof(this->temp), this->temp);

  if (0 == ret_code) {
    this->rsp.copyBufferFrom(rsp_ptr, INFO_RSP_SIZE);
  }

  this->idle();

  return ret_code;
}

uint8_t AtEccX08::getKeySlotConfig(void)
{

  uint8_t *rsp_ptr = &this->temp[ECCX08_BUFFER_POS_DATA];

  this->rsp.clear();

  uint8_t ret_code = this->wakeup();
  if (ret_code != ECCX08_SUCCESS)
    return ret_code;

  memset(this->temp, 0, sizeof(this->temp));

  ret_code = eccX08m_execute(ECCX08_READ,
                             ECCX08_ZONE_CONFIG | ECCX08_ZONE_COUNT_FLAG,
                             64 >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(this->command),
                             this->command, sizeof(this->temp), this->temp);

  if (0 == ret_code) {
    this->rsp.copyBufferFrom(rsp_ptr+24, 2);    //READ_32_RSP_SIZE);  // VERIFY_256_KEY_SIZE);  // READ_32_RSP_SIZE
  }

  this->idle();

  return ret_code;
}

// Use ATECCx08 to generate SHA256 digest. Data must be less than 62 characters long
// for this to work at present. Only handles 1 lot of data.
uint8_t AtEccX08::calculateSHA256( uint8_t *data, int len )
{
    volatile uint8_t ret_code;
    uint8_t *hash = &this->temp[ECCX08_BUFFER_POS_DATA];

    // For now, just limit input size to 62 chars
    if( len > 62 ) {
      return ECCX08_INVALID_SIZE;
    }

    this->rsp.clear();
    this->wakeup();

    // Start SHA256
    ret_code = eccX08m_execute(ECCX08_SHA, SHA_MODE_START, 0x0000,
        0, NULL, 0, NULL, 0, NULL,
        sizeof(this->command), this->command,
        sizeof(this->temp), this->temp);

    if (ret_code == ECCX08_SUCCESS)
    {
        // Send data
        this->wakeup();
/*
        ret_code = eccX08m_execute(ECCX08_SHA, SHA_MODE_UPDATE, len,
          //0,NULL,
                    len, data, 
          0, NULL, 0, NULL,
                    sizeof(this->command), this->command,
                    sizeof(this->temp),this->temp);
        Serial.print(F("SHA256 Update "));
        Serial.println(ret_code, HEX);
*/
    ret_code = eccX08m_execute(ECCX08_SHA, SHA_MODE_END, len, 
        len, data, //0, NULL, 
        0, NULL, 0, NULL,
        sizeof(this->command), this->command,
        sizeof(this->temp), this->temp);

//        Serial.print(F("SHA256 End "));
//        Serial.println(ret_code, HEX);

        this->rsp.copyBufferFrom(hash, 32);
    }


    this->idle();
    return ret_code;
}




// End