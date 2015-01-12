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
#include <AtEcc108.h>
#include <atecc108-atmel/ecc108_physical.h>
#include <atecc108-atmel/ecc108_comm_marshaling.h>
#include <atecc108-atmel/ecc108_lib_return_codes.h>


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

static const uint8_t otp_zone[] =
  {
    0x43, 0x52, 0x59, 0x50, 0x54, 0x52, 0x4f, 0x4e, 0x49, 0x58, 0x20,
    0x43, 0x52, 0x59, 0x50, 0x54, 0x4f, 0x41, 0x55, 0x54, 0x48, 0x20,
    0x41, 0x52, 0x44, 0x55, 0x49, 0x4e, 0x4f, 0x20, 0x53, 0x4f, 0x46,
    0x54, 0x57, 0x41, 0x52, 0x45, 0x20, 0x56, 0x45, 0x52, 0x53, 0x49,
    0x4f, 0x4e, 0x3a, 0x20, 0x30, 0x2e, 0x31, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

AtEcc108::AtEcc108() : ADDRESS(0xC0)
{
    ecc108p_init();
}



AtEcc108::~AtEcc108() { }

void AtEcc108::idle()
{
  ecc108p_idle();
}

uint8_t AtEcc108::wakeup()
{
    uint8_t wakeup_response[ECC108_RSP_SIZE_MIN];

    memset(wakeup_response, 0, sizeof(wakeup_response));
    return ecc108c_wakeup(wakeup_response);
}

const uint8_t AtEcc108::getAddress() const
{
    return this->ADDRESS;
}

uint8_t AtEcc108::getRandom()
{
    volatile uint8_t ret_code;

    uint8_t *random = &this->temp[SHA204_BUFFER_POS_DATA];

    //ret_code = ecc108m_random(this->command, this->temp,
    //RANDOM_NO_SEED_UPDATE);

    this->rsp.clear();
    this->wakeup();

    ret_code = ecc108m_execute(ECC108_RANDOM, RANDOM_NO_SEED_UPDATE, 0x0000, 0,
                               NULL, 0, NULL, 0, NULL, sizeof(this->command),
                               this->command,
                               sizeof(this->temp), this->temp);

    if (ret_code == ECC108_SUCCESS)
    {
        this->rsp.copyBufferFrom(random, 32);
    }


    this->idle();
    return ret_code;
}


const uint8_t AtEcc108::write(uint8_t zone, uint16_t address, uint8_t *new_value,
                              uint8_t *mac, uint8_t size)
{

  if ( !new_value || (zone & ~WRITE_ZONE_MASK))
    // no null pointers allowed
    // zone has to match a valid param1 value.
    return ECC108_BAD_PARAM;

  address >>= 2;
  if ((zone & ECC108_ZONE_MASK) == ECC108_ZONE_CONFIG)
    {
      if (address > ECC108_ADDRESS_MASK_CONFIG)
        return ECC108_BAD_PARAM;
    }
  else if ((zone & ECC108_ZONE_MASK) == ECC108_ZONE_OTP)
    {
      if (address > ECC108_ADDRESS_MASK_OTP)
        return ECC108_BAD_PARAM;
    }
  else if ((zone & ECC108_ZONE_MASK) == ECC108_ZONE_DATA)
    {
      if (address > ECC108_ADDRESS_MASK)
        return ECC108_BAD_PARAM;
    }

  if (ECC108_ZONE_ACCESS_32 != size && ECC108_ZONE_ACCESS_4 != size)
    {
      return ECC108_BAD_PARAM;
    }

  uint8_t param1 = zone;
  uint16_t param2 = (uint8_t) (address & ECC108_ADDRESS_MASK);
  //*p_command++ = 0;

  // count = (zone & ECC108_ZONE_COUNT_FLAG) ?
  //   ECC108_ZONE_ACCESS_32 : ECC108_ZONE_ACCESS_4;

  // if (mac != NULL)
  //   {
  //     memcpy(p_command, mac, WRITE_MAC_SIZE);
  //     p_command += WRITE_MAC_SIZE;
  //   }

  return  ecc108m_execute(ECC108_WRITE, param1, param2, size,
                          new_value, 0, NULL, 0, NULL, sizeof(this->command),
                          this->command,
                          sizeof(this->temp), this->temp);

}


void AtEcc108::burn_config()
  {
    const uint8_t * data = default_config_zone;

    this->rsp.clear();

    for (int x = 0; x < sizeof(default_config_zone); x+=ECC108_ZONE_ACCESS_4)
      {
        this->wakeup();
        this->write(ECC108_ZONE_CONFIG, x, const_cast<uint8_t *>(data+x), NULL,
                    ECC108_ZONE_ACCESS_4);
        this->idle();
      }

  }

void AtEcc108::burn_otp()
{
  const uint8_t * data = otp_zone;

  this->rsp.clear();

  for (int x = 0; x < sizeof(otp_zone); x+=ECC108_ZONE_ACCESS_32)
    {
      this->wakeup();
      this->write(ECC108_ZONE_OTP, x, const_cast<uint8_t *>(data+x), NULL,
                  ECC108_ZONE_ACCESS_32);
      this->idle();
    }

}

uint8_t AtEcc108::lock_config_zone()
{
  uint8_t ret_code;
  uint8_t crc_array[ECC108_CRC_SIZE];
  uint16_t crc;
  uint8_t config_data[ECC108_CONFIG_SIZE];


  ret_code = this->read_config_zone(config_data);
  if (ret_code != ECC108_SUCCESS)
    {
      return ret_code;
    }

  ecc108c_calculate_crc(sizeof(config_data),
                        config_data,
                        crc_array);
  crc = (crc_array[1] << 8) + crc_array[0];

  this->wakeup();
  ret_code = ecc108m_execute(ECC108_LOCK, ECC108_ZONE_CONFIG, crc,
                             0, NULL, 0, NULL, 0, NULL,
                             sizeof(this->command), this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}

uint8_t AtEcc108::lock_data_zone()
{
  uint8_t ret_code;
  uint8_t crc_array[ECC108_CRC_SIZE];
  uint16_t crc;
  uint8_t config_data[ECC108_CONFIG_SIZE];

  this->wakeup();
  ret_code = ecc108m_execute(ECC108_LOCK,
                             LOCK_ZONE_NO_CONFIG | LOCK_ZONE_NO_CRC, 0,
                             0, NULL, 0, NULL, 0, NULL,
                             sizeof(this->command), this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  return ret_code;
}


uint8_t AtEcc108::personalize()
{
  bool config_locked;
  bool data_locked;

  config_locked = this->is_locked(0);
  data_locked = this->is_locked(1);

  if (!config_locked)
    {
      this->burn_config();
      this->lock_config_zone();
    }

  if (!data_locked)
    {
      this->burn_otp();
      this->lock_data_zone();
    }

  return 0;
}


uint8_t AtEcc108::read_config_zone(uint8_t *config_data)
{
  // declared as "volatile" for easier debugging
  volatile uint8_t ret_code;

  uint16_t config_address;

  // Make the command buffer the size of the Read command.
  uint8_t command[READ_COUNT];

  // Make the response buffer the size of the maximum Read response.
  uint8_t response[READ_32_RSP_SIZE];

  // Read first 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
  ret_code = ecc108c_wakeup(response);
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  memset(response, 0, sizeof(response));
  config_address = 0;
  ret_code = ecc108m_execute(ECC108_READ,
                             ECC108_ZONE_CONFIG | ECC108_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  ecc108p_sleep();
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECC108_BUFFER_POS_DATA],
           ECC108_ZONE_ACCESS_32);
    config_data += ECC108_ZONE_ACCESS_32;
  }

  // Read second 32 bytes.
  memset(response, 0, sizeof(response));
  ret_code = ecc108c_wakeup(response);
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  config_address += ECC108_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = ecc108m_execute(ECC108_READ,
                             ECC108_ZONE_CONFIG | ECC108_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  ecc108p_sleep();
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECC108_BUFFER_POS_DATA], ECC108_ZONE_ACCESS_32);
    config_data += ECC108_ZONE_ACCESS_32;
  }

  // Read third 32 bytes.
  memset(response, 0, sizeof(response));
  ret_code = ecc108c_wakeup(response);
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  config_address += ECC108_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = ecc108m_execute(ECC108_READ,
                             ECC108_ZONE_CONFIG | ECC108_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  ecc108p_sleep();
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECC108_BUFFER_POS_DATA], ECC108_ZONE_ACCESS_32);
    config_data += ECC108_ZONE_ACCESS_32;
  }

  // Read foruth 32 bytes.

  memset(response, 0, sizeof(response));
  ret_code = ecc108c_wakeup(response);
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  config_address += ECC108_ZONE_ACCESS_32;
  memset(response, 0, sizeof(response));
  ret_code = ecc108m_execute(ECC108_READ,
                             ECC108_ZONE_CONFIG | ECC108_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(command),
                             command, sizeof(response), response);
  ecc108p_sleep();
  if (ret_code != ECC108_SUCCESS)
    return ret_code;

  if (config_data) {
    memcpy(config_data, &response[ECC108_BUFFER_POS_DATA], ECC108_ZONE_ACCESS_32);
    config_data += ECC108_ZONE_ACCESS_32;
  }


  ecc108p_sleep();

  if (ret_code == ECC108_SUCCESS && config_data) {
    memcpy(config_data, &response[ECC108_BUFFER_POS_DATA],
           ECC108_ZONE_ACCESS_32);
  }

  return ret_code;
}

bool AtEcc108::is_locked(const uint8_t ZONE)
{

  uint16_t config_address = ECC108_ZONE_ACCESS_32 * 2;
  uint8_t *rsp_ptr = &this->temp[ECC108_BUFFER_POS_DATA];
  /* Offset to lock byte */
  uint8_t offset = 22;
  bool status = false;
  uint8_t ret_code;

  this->rsp.clear();

  ret_code = this->wakeup();
  if (ret_code != ECC108_SUCCESS)
    return false;

  this->rsp.clear();

  ret_code = ecc108m_execute(ECC108_READ,
                             ECC108_ZONE_CONFIG | ECC108_ZONE_COUNT_FLAG,
                             config_address >> 2,
                             0, NULL, 0, NULL, 0, NULL, sizeof(this->command),
                             this->command,
                             sizeof(this->temp), this->temp);

  this->idle();

  if (ret_code != ECC108_SUCCESS)
    return false;

  if (ZONE == ECC108_ZONE_CONFIG)
    {
      /* config zone is at offset 23 */
      offset++;
    }

  if (0 == *(rsp_ptr + offset))
    status = true;

  return status;
}
