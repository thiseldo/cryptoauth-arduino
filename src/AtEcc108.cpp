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

AtEcc108::AtEcc108() : ADDRESS(0xC0)
{
    ecc108p_init();
}



AtEcc108::~AtEcc108() { }

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


    ecc108p_idle();
    return ret_code;
}
